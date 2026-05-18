"""
Josias A | 2026
analyzer.py

Security Log Analyzer
Analyzes authentication and firewall logs to detect suspicious
patterns including brute force attempts, port scanning, privilege
escalation, and off-hours activity.

Usage: python analyzer.py <logfile>
"""

import sys
import re
from collections import defaultdict


# -------------------------------------------------------------------
# Configuration: Detection Thresholds
# A SOC team would tune these based on their environment.
# Lower thresholds = more alerts (more false positives).
# Higher thresholds = fewer alerts (risk of missing real attacks).
# -------------------------------------------------------------------
BRUTE_FORCE_THRESHOLD = 5
PORT_SCAN_THRESHOLD = 10
BUSINESS_HOURS_START = 6
BUSINESS_HOURS_END = 22


# -------------------------------------------------------------------
# Log Parsing
# Each log format has its own parser. The parser extracts structured
# data from raw log lines so the detection functions can work with
# clean fields instead of raw text.
# -------------------------------------------------------------------


def parse_auth_log(filepath):
    """
    Parse authentication log entries into structured events.

    Each event is a dictionary with: timestamp, hour, user, source_ip,
    action (accepted/failed), and event_type (login/sudo).
    """
    events = []

    # Pattern for SSH login entries
    # Example: "Mar 15 07:15:33 web-server sshd[1004]: Failed password for admin from 192.168.1.100 port 44512 ssh2"
    ssh_pattern = re.compile(
        r"(\w+ \d+ (\d+):\d+:\d+) \S+ sshd\[\d+\]: "
        r"(Accepted|Failed) password for (?:invalid user )?(\S+) "
        r"from (\S+) port \d+"
    )

    # Pattern for sudo failure entries
    # Example: "Mar 15 09:12:33 web-server sudo: jsmith : authentication failure ; TTY=pts/0 ..."
    sudo_pattern = re.compile(
        r"(\w+ \d+ (\d+):\d+:\d+) \S+ sudo:\s+(\S+)\s*:"
        r".*(?:authentication failure|command not allowed)"
    )

    with open(filepath, "r") as f:
        for line in f:
            # Try matching SSH login pattern first
            ssh_match = ssh_pattern.search(line)
            if ssh_match:
                events.append(
                    {
                        "timestamp": ssh_match.group(1),
                        "hour": int(ssh_match.group(2)),
                        "user": ssh_match.group(4),
                        "source_ip": ssh_match.group(5),
                        "action": ssh_match.group(3).lower(),
                        "event_type": "login",
                    }
                )
                continue

            # Try matching sudo failure pattern
            sudo_match = sudo_pattern.search(line)
            if sudo_match:
                events.append(
                    {
                        "timestamp": sudo_match.group(1),
                        "hour": int(sudo_match.group(2)),
                        "user": sudo_match.group(3),
                        "source_ip": "local",
                        "action": "failed",
                        "event_type": "sudo",
                    }
                )

    return events


def parse_firewall_log(filepath):
    """
    Parse firewall log entries into structured events.

    Each event is a dictionary with: timestamp, hour, source_ip,
    dest_port, protocol, and action (allow/block).
    """
    events = []

    # Pattern for UFW firewall entries
    # Example: "Mar 15 08:00:00 firewall kernel: [UFW BLOCK] IN=eth0 ... SRC=10.0.0.50 ... PROTO=TCP SPT=55001 DPT=21"
    pattern = re.compile(
        r"(\w+ \d+ (\d+):\d+:\d+) \S+ kernel:.*\[UFW (\w+)\].*"
        r"SRC=(\S+).*PROTO=(\S+).*DPT=(\d+)"
    )

    with open(filepath, "r") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                events.append(
                    {
                        "timestamp": match.group(1),
                        "hour": int(match.group(2)),
                        "source_ip": match.group(4),
                        "dest_port": int(match.group(6)),
                        "protocol": match.group(5),
                        "action": match.group(3).lower(),
                    }
                )

    return events


# -------------------------------------------------------------------
# Detection Functions
# Each function looks for one type of suspicious activity.
# They return a list of "findings" — each finding describes what
# was detected, which IP/user was involved, and how severe it is.
# -------------------------------------------------------------------


def detect_brute_force(events):
    """
    Detection: Brute Force (MITRE ATT&CK T1110)

    Counts failed login attempts per source IP. Any IP with failures
    exceeding BRUTE_FORCE_THRESHOLD is flagged. This is the most
    common attack pattern SOC analysts see — automated tools trying
    thousands of username/password combinations against SSH or RDP.
    """
    findings = []

    # Count failed logins per IP address
    # defaultdict(int) starts every new key at 0
    failed_counts = defaultdict(int)

    for event in events:
        if event["event_type"] == "login" and event["action"] == "failed":
            failed_counts[event["source_ip"]] += 1

    # Flag any IP that exceeded the threshold
    for ip, count in failed_counts.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            findings.append(
                {
                    "type": "Brute Force",
                    "mitre_id": "T1110",
                    "severity": "HIGH",
                    "source": ip,
                    "detail": f"{count} failed login attempts",
                }
            )

    return findings


def detect_port_scan(events):
    """
    Detection: Port Scan (MITRE ATT&CK T1046)

    Identifies a single IP connecting to many different destination
    ports. Attackers scan ports to discover which services are running
    on a target — this is usually the first step before exploitation.
    """
    findings = []

    # Track which unique ports each IP has connected to
    # Using a set means duplicate ports don't count twice
    ip_ports = defaultdict(set)

    for event in events:
        ip_ports[event["source_ip"]].add(event["dest_port"])

    # Flag any IP that hit more unique ports than the threshold
    for ip, ports in ip_ports.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            findings.append(
                {
                    "type": "Port Scan",
                    "mitre_id": "T1046",
                    "severity": "MEDIUM",
                    "source": ip,
                    "detail": f"Connected to {len(ports)} unique ports",
                }
            )

    return findings


def detect_privilege_escalation(events):
    """
    Detection: Privilege Escalation (MITRE ATT&CK T1548)

    Flags sudo failures — users trying to run commands as root
    without authorization. This could indicate a compromised account
    trying to gain higher privileges, or an insider threat.
    """
    findings = []

    # Count sudo failures per user
    sudo_failures = defaultdict(int)

    for event in events:
        if event["event_type"] == "sudo" and event["action"] == "failed":
            sudo_failures[event["user"]] += 1

    for user, count in sudo_failures.items():
        findings.append(
            {
                "type": "Privilege Escalation Attempt",
                "mitre_id": "T1548",
                "severity": "HIGH",
                "source": user,
                "detail": f"{count} failed sudo attempt(s)",
            }
        )

    return findings


def detect_suspicious_time(events):
    """
    Detection: Suspicious Time Activity

    Flags authentication events outside business hours. Legitimate
    users rarely log in at 3 AM. Off-hours activity often indicates
    an attacker in a different timezone or automated malicious tools
    running overnight when nobody is watching.
    """
    findings = []

    # Count off-hours events per source
    offhours = defaultdict(int)

    for event in events:
        if event["hour"] < BUSINESS_HOURS_START or event["hour"] >= BUSINESS_HOURS_END:
            key = event.get("source_ip", event.get("user", "unknown"))
            offhours[key] += 1

    # Only flag if there are multiple off-hours events (reduces noise)
    for source, count in offhours.items():
        if count >= 2:
            findings.append(
                {
                    "type":
                    "Off-Hours Activity",
                    "mitre_id":
                    "N/A",
                    "severity":
                    "LOW",
                    "source":
                    source,
                    "detail":
                    f"{count} events outside business hours "
                    f"({BUSINESS_HOURS_START}:00-{BUSINESS_HOURS_END}:00)",
                }
            )

    return findings


# -------------------------------------------------------------------
# Report Generation
# Formats all findings into a readable security report.
# -------------------------------------------------------------------


def generate_report(findings, total_events, log_type):
    """
    Generate a formatted security findings report."""
    print("=" * 60)
    print("  SECURITY LOG ANALYSIS REPORT")
    print(f"  Log type:        {log_type}")
    print(f"  Events analyzed: {total_events}")
    print(f"  Findings:        {len(findings)}")
    print("=" * 60)

    if not findings:
        print("\n  No suspicious activity detected.\n")
        return

    # Group findings by severity for organized output
    for severity in ["HIGH", "MEDIUM", "LOW"]:
        severity_findings = [f for f in findings if f["severity"] == severity]
        if not severity_findings:
            continue

        print(f"\n  [{severity}]")
        print("-" * 60)
        for finding in severity_findings:
            mitre = f" (MITRE {finding['mitre_id']})" if finding["mitre_id"
                                                                 ] != "N/A" else ""
            print(f"  {finding['type']}{mitre}")
            print(f"    Source:  {finding['source']}")
            print(f"    Detail:  {finding['detail']}")
            print()


# -------------------------------------------------------------------
# Main Entry Point
# -------------------------------------------------------------------


def main():
    if len(sys.argv) != 2:
        print("Usage: python analyzer.py <logfile>")
        print("Example: python analyzer.py samples/auth.log")
        sys.exit(1)

    filepath = sys.argv[1]

    # Detect log type from filename and run appropriate detections
    if "auth" in filepath.lower():
        events = parse_auth_log(filepath)
        findings = []
        findings.extend(detect_brute_force(events))
        findings.extend(detect_privilege_escalation(events))
        findings.extend(detect_suspicious_time(events))
        generate_report(findings, len(events), "Authentication Log")

    elif "firewall" in filepath.lower():
        events = parse_firewall_log(filepath)
        findings = []
        findings.extend(detect_port_scan(events))
        findings.extend(detect_suspicious_time(events))
        generate_report(findings, len(events), "Firewall Log")

    else:
        print(f"Unknown log type: {filepath}")
        print("Filename must contain 'auth' or 'firewall'.")
        sys.exit(1)


if __name__ == "__main__":
    main()
