# 🛡️ Security Log Analyzer

A Python-based security log analysis tool that parses Linux `auth.log` and Windows Event Log CSV exports, detects suspicious authentication behavior, and generates human-readable reports.

---

## What It Detects

| Detection | Severity | Description |
|-----------|----------|-------------|
| **Brute Force** | HIGH/MEDIUM | IPs exceeding the failed login threshold |
| **Root Login** | HIGH | Direct SSH login as root |
| **New Accounts** | MEDIUM | User account creation events |
| **After-Hours Login** | LOW | Successful logins outside business hours |

---

## Why I Built This

Log analysis is one of the most common tasks in a SOC (Security Operations Center) or during incident response. Most real tools like Splunk or ELK are expensive and complex. I wanted to understand what's actually happening at the detection logic level — how do you extract signal from thousands of log lines? This tool forced me to work with regex parsing, threshold-based alerting, and report generation from scratch.

---

## Supported Log Types

- **Linux** — `/var/log/auth.log` (SSH, sudo, useradd events)
- **Windows** — Security Event Log exported as CSV (Event IDs: 4624, 4625, 4720, 4728, etc.)

---

## How to Run It

**Requirements:** Python 3.6+, no external dependencies.

```bash
# Basic scan (auto-detects log type, outputs text report)
python analyzer.py /var/log/auth.log

# Generate HTML report instead
python analyzer.py /var/log/auth.log --format html -o my_report

# Generate both formats
python analyzer.py /var/log/auth.log --format both -o investigation

# Adjust brute-force threshold (flag IPs with 10+ failures)
python analyzer.py /var/log/auth.log --threshold 10

# Custom business hours (9am-5pm)
python analyzer.py /var/log/auth.log --biz-start 9 --biz-end 17

# Windows CSV export
python analyzer.py windows_events.csv --type windows --format html

# Use included sample log to test immediately
python analyzer.py sample_auth.log
```

### All Arguments

| Flag | Description | Default |
|------|-------------|---------|
| `logfile` | Path to the log file | Required |
| `--threshold` | Failed logins to trigger brute force alert | 5 |
| `--biz-start` | Business hours start (24h) | 8 |
| `--biz-end` | Business hours end (24h) | 18 |
| `--format` | `text`, `html`, or `both` | text |
| `-o` / `--output` | Output filename (no extension needed) | report |
| `--type` | `linux`, `windows`, or `auto` | auto |

---

## Example Output (Text)

```
=================================================================
SECURITY LOG ANALYSIS REPORT
=================================================================
File analyzed : sample_auth.log
Total events  : 20
Total findings: 6
  HIGH        : 3
  MEDIUM      : 2
  LOW         : 1
=================================================================

─────────────────────────────────────────────────────────────────
  [HIGH] BRUTE FORCE / CREDENTIAL STUFFING (2 finding(s))
─────────────────────────────────────────────────────────────────
  • 192.168.1.105 had 7 failed login attempts targeting: root
    First: 2024-11-15 02:13:45  |  Last: 2024-11-15 02:13:57
  • 10.0.0.55 had 6 failed login attempts targeting: admin, oracle...
    First: 2024-11-15 02:14:01  |  Last: 2024-11-15 02:14:11
```

---

## How It Works

**Parsing:** Regex patterns extract structured fields (timestamp, username, IP) from unstructured log lines. Windows CSV logs are handled with Python's `csv.DictReader`.

**Detection logic:**
- **Brute force** — Groups failed logins by source IP using a `defaultdict`, flags any IP exceeding the threshold
- **After-hours** — Extracts the hour from each successful login timestamp and compares against configurable business hours
- **New accounts** — Pattern-matches `useradd` entries (Linux) or Event ID 4720 (Windows)
- **Root logins** — Specifically watches for `Accepted ... for root` entries or Windows logins with username `root`/`Administrator`

**Reporting:** Results are sorted by severity (HIGH → MEDIUM → LOW) and rendered as either formatted plain text or a self-contained HTML file with color-coded severity badges.

---

## Windows Event IDs Covered

| Event ID | Meaning |
|----------|---------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4720 | New user account created |
| 4728/4756 | User added to security group |
| 4648 | Explicit credential logon |
| 4771 | Kerberos pre-auth failed |

---

## Skills Demonstrated

- Log parsing with regex and Python's `re` module
- CSV processing with `csv.DictReader`
- Threshold-based alerting logic
- Datetime manipulation for time-window detection
- HTML report generation without frameworks
- CLI design with `argparse`
- Security concepts: brute force, privilege escalation, persistence (new accounts)
