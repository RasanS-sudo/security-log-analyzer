#!/usr/bin/env python3
"""
Log Analyzer - Security-focused log analysis tool for auth.log and Windows Event Log exports.
Detects suspicious authentication patterns and generates summary reports.
Author: [Your Name]
"""

import re
import argparse
import sys
import os
import datetime
from collections import defaultdict


BANNER = """
╔═══════════════════════════════════════════╗
║         SECURITY LOG ANALYZER            ║
║     Detect threats. Understand logs.      ║
╚═══════════════════════════════════════════╝
"""

# --- Detection thresholds (tunable via CLI args) ---
DEFAULT_FAILED_LOGIN_THRESHOLD = 5      # Flag IPs with this many failed logins
DEFAULT_BUSINESS_HOURS_START = 8        # 08:00
DEFAULT_BUSINESS_HOURS_END = 18         # 18:00


# ─────────────────────────────────────────────────────────────
# PARSERS
# ─────────────────────────────────────────────────────────────

def parse_auth_log(filepath: str) -> list:
    """
    Parse a Linux /var/log/auth.log file.
    Returns a list of event dicts.
    """
    events = []
    current_year = datetime.datetime.now().year

    # Regex patterns for common auth.log entries
    patterns = {
        "failed_password": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Failed password for (?:invalid user )?(\S+) from (\S+)"
        ),
        "accepted_password": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Accepted (?:password|publickey) for (\S+) from (\S+)"
        ),
        "invalid_user": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Invalid user (\S+) from (\S+)"
        ),
        "new_user": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+).*useradd.*new user: name=(\S+)"
        ),
        "sudo_fail": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+).*sudo.*authentication failure.*user=(\S+)"
        ),
        "root_login": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Accepted.*for root from (\S+)"
        ),
    }

    with open(filepath, "r", errors="replace") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()

            for event_type, pattern in patterns.items():
                match = pattern.search(line)
                if match:
                    groups = match.groups()

                    # Parse timestamp (auth.log has no year, assume current year)
                    try:
                        ts_str = f"{groups[0]} {current_year}"
                        timestamp = datetime.datetime.strptime(ts_str, "%b %d %H:%M:%S %Y")
                    except ValueError:
                        timestamp = None

                    event = {
                        "type": event_type,
                        "timestamp": timestamp,
                        "raw": line,
                        "line_num": line_num,
                    }

                    if event_type in ("failed_password", "accepted_password", "invalid_user"):
                        event["username"] = groups[1] if len(groups) > 1 else "unknown"
                        event["source_ip"] = groups[2] if len(groups) > 2 else "unknown"
                    elif event_type == "new_user":
                        event["username"] = groups[1]
                        event["source_ip"] = "local"
                    elif event_type == "sudo_fail":
                        event["username"] = groups[1]
                        event["source_ip"] = "local"
                    elif event_type == "root_login":
                        event["username"] = "root"
                        event["source_ip"] = groups[1]

                    events.append(event)
                    break  # Only match one pattern per line

    return events


def parse_windows_csv(filepath: str) -> list:
    """
    Parse a Windows Security Event Log exported as CSV.
    Expects columns: TimeCreated, EventID, AccountName, IpAddress, Message
    Returns a list of event dicts.
    """
    import csv
    events = []

    # Windows Event IDs we care about
    WINDOWS_EVENT_MAP = {
        "4624": "successful_login",
        "4625": "failed_login",
        "4720": "new_user_created",
        "4728": "user_added_to_group",
        "4756": "user_added_to_group",
        "4648": "explicit_credential_use",
        "4771": "kerberos_preauth_failed",
    }

    with open(filepath, "r", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for line_num, row in enumerate(reader, 1):
            try:
                event_id = str(row.get("EventID", "")).strip()
                event_type = WINDOWS_EVENT_MAP.get(event_id, f"event_{event_id}")

                # Try to parse timestamp
                ts_raw = row.get("TimeCreated", "")
                try:
                    timestamp = datetime.datetime.fromisoformat(ts_raw)
                except (ValueError, TypeError):
                    timestamp = None

                event = {
                    "type": event_type,
                    "timestamp": timestamp,
                    "username": row.get("AccountName", "unknown").strip(),
                    "source_ip": row.get("IpAddress", "unknown").strip(),
                    "event_id": event_id,
                    "raw": str(row),
                    "line_num": line_num,
                }
                events.append(event)

            except Exception:
                continue  # Skip malformed rows

    return events


def detect_log_type(filepath: str) -> str:
    """Auto-detect whether the log is auth.log or Windows CSV."""
    _, ext = os.path.splitext(filepath)
    if ext.lower() == ".csv":
        return "windows"

    # Peek at file content
    with open(filepath, "r", errors="replace") as f:
        sample = f.read(500)
    if "sshd" in sample or "useradd" in sample or "sudo" in sample:
        return "linux"
    if "EventID" in sample or "TimeCreated" in sample:
        return "windows"

    return "linux"  # Default fallback


# ─────────────────────────────────────────────────────────────
# DETECTIONS
# ─────────────────────────────────────────────────────────────

def detect_brute_force(events: list, threshold: int) -> list:
    """Flag IPs with failed login attempts above the threshold."""
    fail_types = {"failed_password", "invalid_user", "failed_login", "kerberos_preauth_failed"}
    counts = defaultdict(lambda: {"count": 0, "usernames": set(), "times": []})

    for e in events:
        if e["type"] in fail_types:
            ip = e.get("source_ip", "unknown")
            counts[ip]["count"] += 1
            counts[ip]["usernames"].add(e.get("username", "unknown"))
            if e["timestamp"]:
                counts[ip]["times"].append(e["timestamp"])

    findings = []
    for ip, data in counts.items():
        if data["count"] >= threshold:
            findings.append({
                "type": "BRUTE_FORCE",
                "severity": "HIGH" if data["count"] >= threshold * 3 else "MEDIUM",
                "source_ip": ip,
                "count": data["count"],
                "usernames_targeted": list(data["usernames"]),
                "first_seen": min(data["times"]).strftime("%Y-%m-%d %H:%M:%S") if data["times"] else "unknown",
                "last_seen": max(data["times"]).strftime("%Y-%m-%d %H:%M:%S") if data["times"] else "unknown",
                "description": f"{ip} had {data['count']} failed login attempts targeting: {', '.join(list(data['usernames'])[:5])}"
            })

    return sorted(findings, key=lambda x: x["count"], reverse=True)


def detect_after_hours_logins(events: list, hour_start: int, hour_end: int) -> list:
    """Flag successful logins that occurred outside business hours."""
    success_types = {"accepted_password", "successful_login"}
    findings = []

    for e in events:
        if e["type"] in success_types and e["timestamp"]:
            hour = e["timestamp"].hour
            if hour < hour_start or hour >= hour_end:
                findings.append({
                    "type": "AFTER_HOURS_LOGIN",
                    "severity": "LOW",
                    "username": e.get("username", "unknown"),
                    "source_ip": e.get("source_ip", "unknown"),
                    "timestamp": e["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                    "description": f"Login by '{e.get('username')}' from {e.get('source_ip')} at {e['timestamp'].strftime('%H:%M')} (outside {hour_start:02d}:00-{hour_end:02d}:00)"
                })

    return findings


def detect_new_accounts(events: list) -> list:
    """Flag new user account creation events."""
    create_types = {"new_user", "new_user_created"}
    findings = []

    for e in events:
        if e["type"] in create_types:
            findings.append({
                "type": "NEW_ACCOUNT",
                "severity": "MEDIUM",
                "username": e.get("username", "unknown"),
                "source_ip": e.get("source_ip", "local"),
                "timestamp": e["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if e["timestamp"] else "unknown",
                "description": f"New user account created: '{e.get('username')}'"
            })

    return findings


def detect_root_logins(events: list) -> list:
    """Flag direct root logins — always suspicious."""
    findings = []

    for e in events:
        if e["type"] == "root_login" or (e.get("username") == "root" and e["type"] in ("accepted_password", "successful_login")):
            findings.append({
                "type": "ROOT_LOGIN",
                "severity": "HIGH",
                "username": "root",
                "source_ip": e.get("source_ip", "unknown"),
                "timestamp": e["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if e["timestamp"] else "unknown",
                "description": f"Direct root login from {e.get('source_ip', 'unknown')}"
            })

    return findings


# ─────────────────────────────────────────────────────────────
# REPORTING
# ─────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def generate_text_report(filepath: str, events: list, findings: list, args) -> str:
    """Generate a plain-text summary report."""
    all_findings = []
    for group in findings.values():
        all_findings.extend(group)
    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))

    high = [f for f in all_findings if f["severity"] == "HIGH"]
    medium = [f for f in all_findings if f["severity"] == "MEDIUM"]
    low = [f for f in all_findings if f["severity"] == "LOW"]

    lines = []
    lines.append("=" * 65)
    lines.append("SECURITY LOG ANALYSIS REPORT")
    lines.append("=" * 65)
    lines.append(f"File analyzed : {filepath}")
    lines.append(f"Total events  : {len(events)}")
    lines.append(f"Total findings: {len(all_findings)}")
    lines.append(f"  HIGH        : {len(high)}")
    lines.append(f"  MEDIUM      : {len(medium)}")
    lines.append(f"  LOW         : {len(low)}")
    lines.append(f"Generated     : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 65)

    if not all_findings:
        lines.append("\n[✓] No suspicious activity detected.")
        return "\n".join(lines)

    def add_section(title, items):
        if not items:
            return
        lines.append(f"\n{'─' * 65}")
        lines.append(f"  [{items[0]['severity']}] {title} ({len(items)} finding(s))")
        lines.append(f"{'─' * 65}")
        for item in items:
            lines.append(f"  • {item['description']}")
            if "first_seen" in item:
                lines.append(f"    First: {item['first_seen']}  |  Last: {item['last_seen']}")
            elif "timestamp" in item:
                lines.append(f"    Time : {item['timestamp']}")

    add_section("BRUTE FORCE / CREDENTIAL STUFFING", findings.get("brute_force", []))
    add_section("ROOT LOGINS", findings.get("root_logins", []))
    add_section("NEW ACCOUNTS CREATED", findings.get("new_accounts", []))
    add_section("AFTER-HOURS LOGINS", findings.get("after_hours", []))

    lines.append("\n" + "=" * 65)
    lines.append("END OF REPORT")
    lines.append("=" * 65)

    return "\n".join(lines)


def generate_html_report(filepath: str, events: list, findings: list, args) -> str:
    """Generate an HTML summary report."""
    all_findings = []
    for group in findings.values():
        all_findings.extend(group)

    high = [f for f in all_findings if f["severity"] == "HIGH"]
    medium = [f for f in all_findings if f["severity"] == "MEDIUM"]
    low = [f for f in all_findings if f["severity"] == "LOW"]

    severity_colors = {"HIGH": "#e74c3c", "MEDIUM": "#e67e22", "LOW": "#f1c40f"}

    rows = ""
    for f in sorted(all_findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 9)):
        color = severity_colors.get(f["severity"], "#999")
        timestamp = f.get("timestamp", f.get("last_seen", "—"))
        rows += f"""
        <tr>
            <td><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-weight:bold">{f['severity']}</span></td>
            <td>{f['type'].replace('_', ' ')}</td>
            <td>{f['description']}</td>
            <td>{timestamp}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Log Report</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a2e; color: #eee; margin: 0; padding: 20px; }}
  h1 {{ color: #e94560; }}
  .meta {{ color: #aaa; font-size: 0.9em; margin-bottom: 20px; }}
  .cards {{ display: flex; gap: 15px; margin: 20px 0; }}
  .card {{ background: #16213e; border-radius: 8px; padding: 15px 25px; flex: 1; text-align: center; }}
  .card .num {{ font-size: 2em; font-weight: bold; }}
  .card.high .num {{ color: #e74c3c; }}
  .card.medium .num {{ color: #e67e22; }}
  .card.low .num {{ color: #f1c40f; }}
  .card.total .num {{ color: #3498db; }}
  table {{ width: 100%; border-collapse: collapse; background: #16213e; border-radius: 8px; overflow: hidden; }}
  th {{ background: #0f3460; padding: 12px; text-align: left; color: #e94560; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #0f3460; vertical-align: top; }}
  tr:hover td {{ background: #0f3460; }}
  .none {{ color: #2ecc71; font-size: 1.1em; margin: 30px 0; }}
</style>
</head>
<body>
<h1>🔐 Security Log Analysis Report</h1>
<div class="meta">
  <strong>File:</strong> {filepath} &nbsp;|&nbsp;
  <strong>Events Parsed:</strong> {len(events)} &nbsp;|&nbsp;
  <strong>Generated:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
</div>

<div class="cards">
  <div class="card total"><div class="num">{len(all_findings)}</div><div>Total Findings</div></div>
  <div class="card high"><div class="num">{len(high)}</div><div>High Severity</div></div>
  <div class="card medium"><div class="num">{len(medium)}</div><div>Medium Severity</div></div>
  <div class="card low"><div class="num">{len(low)}</div><div>Low Severity</div></div>
</div>

{"<p class='none'>✅ No suspicious activity detected.</p>" if not all_findings else f"""
<table>
  <thead><tr><th>Severity</th><th>Type</th><th>Description</th><th>Timestamp</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""}

</body>
</html>"""

    return html


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Security Log Analyzer — detect threats in auth.log and Windows Event Logs",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("logfile", help="Path to the log file (auth.log or Windows CSV export)")
    parser.add_argument("--threshold", type=int, default=DEFAULT_FAILED_LOGIN_THRESHOLD,
                        help=f"Failed login threshold for brute force detection (default: {DEFAULT_FAILED_LOGIN_THRESHOLD})")
    parser.add_argument("--biz-start", type=int, default=DEFAULT_BUSINESS_HOURS_START,
                        help=f"Business hours start (24h, default: {DEFAULT_BUSINESS_HOURS_START})")
    parser.add_argument("--biz-end", type=int, default=DEFAULT_BUSINESS_HOURS_END,
                        help=f"Business hours end (24h, default: {DEFAULT_BUSINESS_HOURS_END})")
    parser.add_argument("--format", choices=["text", "html", "both"], default="text",
                        help="Output format: text, html, or both (default: text)")
    parser.add_argument("-o", "--output", type=str,
                        help="Output file name (auto-extension added). Default: report")
    parser.add_argument("--type", choices=["linux", "windows", "auto"], default="auto",
                        help="Log type. auto = auto-detect (default)")

    args = parser.parse_args()

    # Validate file exists
    if not os.path.isfile(args.logfile):
        print(f"[ERROR] File not found: {args.logfile}")
        sys.exit(1)

    # Detect log type
    log_type = args.type if args.type != "auto" else detect_log_type(args.logfile)
    print(f"[*] Log type   : {log_type.upper()}")
    print(f"[*] File       : {args.logfile}")
    print(f"[*] Thresholds : Failed logins >= {args.threshold} | Business hours {args.biz_start:02d}:00-{args.biz_end:02d}:00")

    # Parse
    print("[*] Parsing log file...")
    if log_type == "linux":
        events = parse_auth_log(args.logfile)
    else:
        events = parse_windows_csv(args.logfile)

    print(f"[*] Parsed {len(events)} events")

    # Run detections
    print("[*] Running detections...")
    findings = {
        "brute_force": detect_brute_force(events, args.threshold),
        "after_hours": detect_after_hours_logins(events, args.biz_start, args.biz_end),
        "new_accounts": detect_new_accounts(events),
        "root_logins": detect_root_logins(events),
    }

    total = sum(len(v) for v in findings.values())
    print(f"[*] Detections complete: {total} finding(s)")

    # Generate and output report
    output_base = args.output or "report"

    if args.format in ("text", "both"):
        report_text = generate_text_report(args.logfile, events, findings, args)
        print("\n" + report_text)
        txt_path = output_base + ".txt"
        with open(txt_path, "w") as f:
            f.write(report_text)
        print(f"\n[+] Text report saved: {txt_path}")

    if args.format in ("html", "both"):
        report_html = generate_html_report(args.logfile, events, findings, args)
        html_path = output_base + ".html"
        with open(html_path, "w") as f:
            f.write(report_html)
        print(f"[+] HTML report saved: {html_path}")


if __name__ == "__main__":
    main()
