<!-- Josias A | 2026 -->
<!-- README.md -->

# Security Log Analyzer

A Python-based security log analysis tool that detects common attack patterns in authentication and firewall logs. Built for Security Operations Center (SOC) environments where analysts need to quickly identify brute force attempts, port scans, privilege escalation, and suspicious off-hours activity.

In a real SOC, analysts spend the majority of their time reviewing logs from SIEMs like Splunk or Elastic. This tool demonstrates the core detection logic that powers those alerts — pattern matching, threshold-based detection, and severity classification — in a straightforward, readable Python script.

## Attack Types Detected

| Detection | MITRE ATT&CK ID | Severity | Method |
|-----------|-----------------|----------|--------|
| Brute Force | T1110 | HIGH | Count failed login attempts per source IP; flag IPs exceeding threshold |
| Port Scan | T1046 | MEDIUM | Track unique destination ports per source IP; flag IPs scanning many ports |
| Privilege Escalation | T1548 | HIGH | Flag sudo failures and unauthorized command attempts |
| Off-Hours Activity | N/A | LOW | Flag authentication events outside business hours (06:00-22:00) |

### Brute Force (T1110)

Brute force attacks use automated tools to try thousands of username/password combinations against services like SSH or RDP. This is one of the most common attack vectors SOC analysts encounter. The tool counts failed login attempts per source IP and flags any IP exceeding the configured threshold (default: 5 failures).

### Port Scan (T1046)

Port scanning is typically the first step in an attack — the attacker probes a target to discover which services are running and which ports are open. The tool tracks unique destination ports per source IP and flags any IP that connects to more ports than the threshold (default: 10 unique ports).

### Privilege Escalation (T1548)

When an attacker gains access to a low-privilege account, they often attempt to escalate to root/admin. The tool detects sudo failures — users trying to run commands as root without authorization. This could indicate a compromised account or an insider threat.

### Off-Hours Activity

Legitimate users rarely authenticate at 3 AM. Activity outside business hours (configurable, default 06:00-22:00) often indicates an attacker operating from a different timezone or automated malware running when nobody is watching.

## How to Run

```bash
python analyzer.py samples/auth.log
python analyzer.py samples/firewall.log
```

No dependencies required — uses only Python standard library.

## Sample Output

### Authentication Log Analysis

```
============================================================
  SECURITY LOG ANALYSIS REPORT
============================================================
  Log type:        Authentication Log
  Events analyzed: 50
  Findings:        4
============================================================

  [HIGH]
------------------------------------------------------------
  Brute Force (MITRE T1110)
    Source:  192.168.1.100
    Detail:  15 failed login attempts

  Privilege Escalation Attempt (MITRE T1548)
    Source:  jsmith
    Detail:  2 failed sudo attempt(s)

  Privilege Escalation Attempt (MITRE T1548)
    Source:  intern
    Detail:  1 failed sudo attempt(s)


  [LOW]
------------------------------------------------------------
  Off-Hours Activity
    Source:  198.51.100.77
    Detail:  6 events outside business hours (6:00-22:00)
```

### Firewall Log Analysis

```
============================================================
  SECURITY LOG ANALYSIS REPORT
============================================================
  Log type:        Firewall Log
  Events analyzed: 44
  Findings:        2
============================================================

  [MEDIUM]
------------------------------------------------------------
  Port Scan (MITRE T1046)
    Source:  10.0.0.50
    Detail:  Connected to 17 unique ports


  [LOW]
------------------------------------------------------------
  Off-Hours Activity
    Source:  198.51.100.77
    Detail:  4 events outside business hours (6:00-22:00)
```

## Configuration

Detection thresholds are configured at the top of `analyzer.py`:

| Variable | Default | Purpose |
|----------|---------|---------|
| `BRUTE_FORCE_THRESHOLD` | 5 | Failed logins from same IP to trigger alert |
| `PORT_SCAN_THRESHOLD` | 10 | Unique ports from same IP to trigger alert |
| `BUSINESS_HOURS_START` | 6 | Start of business hours (24h format) |
| `BUSINESS_HOURS_END` | 22 | End of business hours (24h format) |

A SOC team would tune these thresholds based on their environment. Lower thresholds catch more attacks but generate more false positives. Higher thresholds reduce noise but risk missing real threats.

## What I Learned

<!-- Write 3-5 sentences about what you learned from studying and
working with this project. What concepts were new to you?
How would you explain this tool in a job interview? -->
# log-analyzer-1
