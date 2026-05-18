<!-- © AngelaMos | 2026 -->
<!-- study-guide.md -->

# Log Analyzer — Study Guide for Derek

> This document is for your personal study only. It does NOT go on your GitHub.

---

## How to Run It

You just need Python installed. The script uses only built-in Python libraries (no extra installs needed).

**Check if you have Python:**
```bash
python3 --version
```
If that shows Python 3.x, you're good.

**Run it:**
```bash
python3 analyzer.py samples/auth.log
python3 analyzer.py samples/firewall.log
```

That's it. No pip install, no setup, no virtual environment. Just Python.

---

## How to Study This Project

1. Read the README first — understand what the tool does at a high level
2. Run the tool against both sample logs and look at the output
3. Open `analyzer.py` and read through it section by section (use this guide)
4. Try the exercises at the bottom
5. Practice explaining the project out loud as if you're in an interview

---

## Big Picture: How the Code Actually Works

Before reading any code, here's the mental model:

```
Raw log file  →  Parser  →  List of events  →  Detectors  →  List of findings  →  Report
```

That's literally it. The whole script does those five things in order.

1. **Parser** — reads the messy log file line by line, pulls out the useful fields (IP, timestamp, action), and turns each line into a clean Python dictionary. Like sorting mail.

2. **Events** — a list of those dictionaries. At this point the data is structured and easy to work with.

3. **Detectors** — each detection (brute force, port scan, etc.) is its own function. They all take that events list, look for their specific pattern, and return findings. They don't know about each other.

4. **Findings** — same idea as events: a list of dictionaries describing what was suspicious.

5. **Report** — takes all findings, sorts them by severity (HIGH → MEDIUM → LOW), and prints them.

If you understand that flow, you understand the whole project. The details inside each function are just the implementation.

---

## Line-by-Line Walkthrough

### Configuration Section (Lines 22-25)

```python
BRUTE_FORCE_THRESHOLD = 5
PORT_SCAN_THRESHOLD = 10
BUSINESS_HOURS_START = 6
BUSINESS_HOURS_END = 22
```

These are the detection thresholds. Think of them as "how sensitive is the alarm."

- If you set `BRUTE_FORCE_THRESHOLD = 3`, you'd catch more attacks but also flag someone who just mistyped their password 3 times (false positive).
- If you set it to `50`, you'd only catch massive automated attacks but miss smaller ones.
- In a real SOC, tuning these is a constant balancing act. There's no perfect number — it depends on the environment.

### parse_auth_log (Lines 34-75)

This function reads a log file line by line and uses **regex (regular expressions)** to extract structured data.

**What regex does:** It's pattern matching. The pattern `r"(Accepted|Failed) password for (\S+) from (\S+)"` means:
- Find either "Accepted" or "Failed"
- Then "password for"
- Then capture the username (any non-space characters)
- Then "from"
- Then capture the IP address

**What comes out:** Each log line becomes a clean dictionary like:
```python
{
    "timestamp": "Mar 15 07:15:33",
    "hour": 7,
    "user": "admin",
    "source_ip": "192.168.1.100",
    "action": "failed",
    "event_type": "login"
}
```

This is called **parsing** — turning messy raw text into structured data you can analyze.

### parse_firewall_log (Lines 78-103)

Same idea as the auth parser, different log format. Firewall logs contain:
- Source IP (who's connecting)
- Destination port (what service they're trying to reach)
- Protocol (TCP or UDP)
- Action (ALLOW or BLOCK)

### detect_brute_force (Lines 112-133)

```python
failed_counts = defaultdict(int)
for event in events:
    if event["event_type"] == "login" and event["action"] == "failed":
        failed_counts[event["source_ip"]] += 1
```

**What `defaultdict(int)` does:** It's a dictionary where every new key starts at 0. So `failed_counts["192.168.1.100"] += 1` works even the first time — it starts at 0 and becomes 1.

**The logic:** Loop through every event. If it's a failed login, add 1 to that IP's counter. After counting, check which IPs exceeded the threshold.

**Why this matters in a SOC:** This is literally what SIEM correlation rules do. A Splunk alert for brute force is doing this same counting logic, just at scale across millions of log entries.

### detect_port_scan (Lines 136-155)

```python
ip_ports = defaultdict(set)
for event in events:
    ip_ports[event["source_ip"]].add(event["dest_port"])
```

**What `set` does:** A set only stores unique values. If an IP connects to port 80 ten times, the set still only contains `{80}`. We care about how many DIFFERENT ports were hit, not how many connections total.

**The logic:** Track which unique ports each IP connected to. If an IP hit more unique ports than the threshold, it's probably scanning.

### detect_privilege_escalation (Lines 158-176)

Counts sudo failures per user. Simpler than brute force because there's no threshold check — any sudo failure gets flagged. In a real environment, you might add a threshold here too.

### detect_suspicious_time (Lines 179-200)

Checks the hour of each event against business hours. The `hour` field was extracted during parsing (from the timestamp).

### generate_report (Lines 207-232)

Formats findings into a readable report grouped by severity (HIGH, MEDIUM, LOW). This is what you'd see in a SIEM dashboard or an analyst's daily report.

---

## Key Concepts for Security+

This project directly covers several Security+ Domain 4 (Security Operations) topics:

### SIEM and Log Analysis
A SIEM (Security Information and Event Management) collects logs from across the network — firewalls, servers, endpoints — and correlates them to detect threats. This tool does the same thing at a smaller scale. When an interviewer asks "have you worked with SIEM tools," you can say "I built a log analysis tool that implements the same detection logic — threshold-based alerting, pattern matching, and severity classification."

### MITRE ATT&CK Framework
MITRE ATT&CK is a knowledge base of adversary tactics and techniques based on real-world observations. Each technique has a unique ID:
- **T1110 (Brute Force)** — automated credential guessing
- **T1046 (Network Service Scanning)** — port scanning to discover services
- **T1548 (Abuse Elevation Control Mechanism)** — privilege escalation attempts

SOC teams map their detection rules to ATT&CK techniques so everyone speaks the same language. When you see an alert tagged "T1110," you immediately know what kind of attack it is.

### False Positives vs False Negatives
- **False positive:** The tool flags something as suspicious that's actually legitimate (e.g., a sysadmin working late gets flagged by the off-hours detection)
- **False negative:** The tool misses an actual attack (e.g., an attacker does 4 failed logins but the threshold is 5)

Tuning thresholds is about finding the balance. This is one of the most common SOC interview questions.

### Indicators of Compromise (IOCs)
IOCs are artifacts that indicate a potential security incident:
- IP addresses (192.168.1.100 doing brute force)
- Usernames (intern trying sudo commands they shouldn't)
- Timestamps (activity at 2 AM)
- Port patterns (one IP hitting 17 different ports)

When you find IOCs, you document them and use them to hunt for related activity across other systems.

---

## Why This Matters in a SOC

### If you see a Brute Force alert:
1. Check if the source IP is internal or external
2. Check if any of the login attempts succeeded (that's worse)
3. If external: block the IP at the firewall, check for compromised accounts
4. If internal: could be a compromised machine or insider threat
5. Document the IOCs (IP address, usernames targeted, timestamps)

### If you see a Port Scan:
1. Determine if it's from inside or outside the network
2. External scan: usually automated reconnaissance. Block the IP, note it.
3. Internal scan: more concerning — could be lateral movement from a compromised host
4. Check what ports were scanned — database ports (3306, 5432) are more concerning than web ports

### If you see Privilege Escalation:
1. Identify the user account immediately
2. Check if the account is compromised or if the actual user did it
3. Check what commands they tried to run
4. If compromised: disable the account, investigate how access was gained
5. If legitimate user: it might be a policy violation (report to management)

### If you see Off-Hours Activity:
1. Check if it's a known service account or cron job (normal)
2. Check the source IP — is it from an unusual location?
3. Cross-reference with other detections (off-hours + brute force = bad)
4. Could be an attacker in a different timezone

---

## Interview Q&A Prep

### "Tell me about a project you've built."

> "I built a security log analyzer in Python that detects common attack patterns in authentication and firewall logs. It parses raw log files, identifies brute force attempts, port scans, privilege escalation, and suspicious off-hours activity, and generates a severity-rated findings report. Each detection maps to a MITRE ATT&CK technique — for example, the brute force detection maps to T1110. The tool uses threshold-based detection, which is the same fundamental approach that enterprise SIEMs use for their correlation rules."

### "How does your brute force detection work?"

> "It counts failed login attempts per source IP address. If any single IP exceeds the configured threshold — I set mine to 5 — it gets flagged as a HIGH severity finding. This is the same logic that Splunk or Elastic SIEM correlation rules use, just at a smaller scale. In a real SOC, you'd tune this threshold based on your environment — too low and you get false positives from people mistyping passwords, too high and you miss attacks."

### "What is a false positive? Give an example from your project."

> "A false positive is when the tool flags something as suspicious that's actually legitimate. For example, my off-hours detection might flag a system administrator who legitimately works night shifts, or a scheduled backup service that runs at 2 AM. That's why detection thresholds and context matter — you can't just blindly trust alerts, you need to investigate each one."

### "What is MITRE ATT&CK and how did you use it?"

> "MITRE ATT&CK is a knowledge base of adversary tactics and techniques based on real-world observations. Each technique has a unique ID — like T1110 for Brute Force. I mapped each of my detection rules to the corresponding ATT&CK technique so that findings can be understood in the context of the broader threat landscape. This is standard practice in SOC environments — SIEM rules typically map to ATT&CK techniques for consistent reporting."

### "How would you improve this tool?"

> "A few ways. First, I'd add time-window correlation — right now the brute force detection counts all failures across the entire log, but in reality you'd want to look at failures within a specific time window, like 5 failures in 10 minutes. Second, I'd add IP reputation lookups using threat intelligence feeds to automatically flag known malicious IPs. Third, I'd add log rotation handling so it can process logs across multiple files. And fourth, I'd output findings in JSON format so they could be ingested by a SIEM for further correlation."

---

## Exercises

1. **Change the brute force threshold from 5 to 10.** Run the tool again. Does 192.168.1.100 still get flagged? Why? (Answer: yes, it has 15 failures. But a smaller attacker with 7 attempts would now be missed.)

2. **Add a new log entry to auth.log.** Add a line with a new IP doing 6 failed logins. Run the tool. Does it get caught?

3. **Explain what a false positive is** and give an example from the off-hours detection. (Answer: a legitimate sysadmin working late, a scheduled backup service, a user in a different timezone.)

4. **What would you add as a 5th detection rule?** Describe the attack pattern, the detection logic, and what MITRE technique it maps to. (Good answers: geographically impossible login, T1078; login from a known-bad IP using threat intel, T1133; multiple accounts from the same IP, T1078.001)

5. **Run the tool against both log files and explain every finding in plain English** — pretend you're writing an email to your SOC team lead summarizing what you found today.
