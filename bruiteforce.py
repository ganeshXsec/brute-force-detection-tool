#!/usr/bin/env python3
"""Detect repeated failed logins in a CSV-style authentication log.

Expected log format:
timestamp,src_ip,username,status
2026-10-28 09:00:00,192.0.2.10,admin,FAILED
"""

import argparse
import csv
import ipaddress
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
import sys


REQUIRED_COLUMNS = {"timestamp", "src_ip", "username", "status"}
FAILURE_VALUES = {"FAIL", "FAILED", "FAILURE", "DENIED", "INVALID"}
SUCCESS_VALUES = {"SUCCESS", "SUCCEEDED", "OK", "ACCEPTED"}


def valid_ip(value):
    """Return a normalized IP address, or None if invalid."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def parse_timestamp(value):
    """Check common ISO-like timestamps. Return None if parsing fails."""
    value = value.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def analyze_log(log_path, threshold):
    failures_by_ip = Counter()
    usernames_by_ip = defaultdict(set)
    first_seen = {}
    last_seen = {}
    total_rows = 0
    skipped_rows = 0
    successful_logins = 0

    with log_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("The log file is empty or has no CSV header.")

        reader.fieldnames = [name.strip().lower() for name in reader.fieldnames]
        missing = REQUIRED_COLUMNS - set(reader.fieldnames)
        if missing:
            raise ValueError(
                "Missing required CSV columns: " + ", ".join(sorted(missing))
            )

        for row in reader:
            total_rows += 1
            row = {(key or "").strip().lower(): (value or "").strip()
                   for key, value in row.items()}

            ip = valid_ip(row.get("src_ip", ""))
            status = row.get("status", "").upper()
            username = row.get("username", "")
            timestamp_text = row.get("timestamp", "")
            timestamp = parse_timestamp(timestamp_text)

            if ip is None or not username or not timestamp_text:
                skipped_rows += 1
                continue

            if status in FAILURE_VALUES:
                failures_by_ip[ip] += 1
                usernames_by_ip[ip].add(username)
                if ip not in first_seen:
                    first_seen[ip] = timestamp_text
                last_seen[ip] = timestamp_text
            elif status in SUCCESS_VALUES:
                successful_logins += 1
            else:
                skipped_rows += 1

    findings = []
    for ip, count in failures_by_ip.most_common():
        if count >= threshold:
            findings.append({
                "src_ip": ip,
                "failed_attempts": count,
                "severity": "HIGH" if count >= threshold * 2 else "MEDIUM",
                "targeted_usernames": ";".join(sorted(usernames_by_ip[ip])),
                "first_seen": first_seen[ip],
                "last_seen": last_seen[ip],
                "alert": f"{count} failed login attempts from {ip}",
            })

    summary = {
        "total_rows": total_rows,
        "skipped_rows": skipped_rows,
        "successful_logins": successful_logins,
        "unique_ips_with_failures": len(failures_by_ip),
        "alerts": len(findings),
    }
    return findings, summary


def write_report(findings, output_path):
    fieldnames = [
        "src_ip", "failed_attempts", "severity", "targeted_usernames",
        "first_seen", "last_seen", "alert"
    ]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)


def main():
    parser = argparse.ArgumentParser(
        description="Detect repeated failed logins from authentication logs."
    )
    parser.add_argument("--log", default="sample.log", help="Path to input CSV log (default: sample.log)")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Failed attempts per IP needed to alert (default: 5)")
    parser.add_argument("--output", default="report.csv", help="Output CSV report (default: report.csv)")
    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")

    log_path = Path(args.log)
    output_path = Path(args.output)

    if not log_path.is_file():
        print(f"[ERROR] Log file not found: {log_path}", file=sys.stderr)
        return 1

    try:
        findings, summary = analyze_log(log_path, args.threshold)
        write_report(findings, output_path)
    except (OSError, ValueError, csv.Error) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    print("\n=== Brute-Force Detection Summary ===")
    print(f"Input file                 : {log_path}")
    print(f"Rows processed             : {summary['total_rows']}")
    print(f"Rows skipped               : {summary['skipped_rows']}")
    print(f"Successful login events    : {summary['successful_logins']}")
    print(f"IPs with failed logins     : {summary['unique_ips_with_failures']}")
    print(f"Alerts generated           : {summary['alerts']}")
    print(f"CSV report                 : {output_path}")

    if findings:
        print("\nPotential brute-force activity:")
        for finding in findings:
            print(
                f"- [{finding['severity']}] {finding['src_ip']}: "
                f"{finding['failed_attempts']} failed attempts; "
                f"users: {finding['targeted_usernames']}"
            )
    else:
        print("\nNo IP exceeded the configured threshold.")

    print("\nNote: An alert is a lead for investigation, not proof of malicious activity.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
