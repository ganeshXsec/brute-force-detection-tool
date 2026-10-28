# Brute-Force Attack Detection Tool

A beginner-friendly Python project for a SOC Analyst portfolio. It analyzes authentication logs, counts failed login attempts by source IP, and generates a CSV alert report when an IP reaches a configurable threshold.

> **Important:** This tool demonstrates a simple detection heuristic. Repeated failures may be caused by user error, a misconfigured service, or malicious activity. Investigate before classifying an event as an attack.

## Features

- Parses CSV authentication logs
- Counts failed login attempts by source IP
- Flags IPs at or above a configurable threshold
- Assigns `MEDIUM` or `HIGH` severity based on the count
- Records targeted usernames and first/last observed timestamps
- Exports findings to `report.csv`
- Uses Python's standard library; no third-party packages required

## Requirements

- Python 3.9 or later
- Windows, Linux, or macOS

## Project structure

```text
brute-force-detection-tool/
├── analyzer.py
├── sample.log
├── README.md
├── requirements.txt
└── .gitignore
```

## Run on Windows

1. Install Python 3 if it is not already installed. During installation, select **Add Python to PATH**.
2. Download or clone this repository.
3. Open Command Prompt or PowerShell in the project folder.
4. Run:

```bash
python analyzer.py
```

To set a different threshold or file path:

```bash
python analyzer.py --log sample.log --threshold 5 --output report.csv
```

If your system uses the Python launcher, use `py analyzer.py` instead.

## Input log format

The input must be a CSV file with these column names:

```csv
timestamp,src_ip,username,status
2026-10-28 09:00:00,192.0.2.10,admin,FAILED
```

Accepted failure status values include `FAIL`, `FAILED`, `FAILURE`, `DENIED`, and `INVALID`. Accepted success values include `SUCCESS`, `SUCCEEDED`, `OK`, and `ACCEPTED`.

The sample file uses documentation-only IP ranges; these are illustrative examples, not real attacker addresses.

## Example output

The sample data should generate alerts for `192.0.2.10` and `203.0.113.7` with the default threshold of 5. The exact output also includes summary counts and the path to `report.csv`.

## How detection works

1. Read each CSV event.
2. Validate the source IP.
3. Count failed authentication events per IP.
4. If the count is greater than or equal to the configured threshold, create an alert.
5. Assign `HIGH` severity at twice the threshold; otherwise assign `MEDIUM`.
6. Export findings to CSV for review.

This starter version counts across the whole file; it does not implement a rolling time window, geolocation, automatic blocking, or live monitoring.

## Suggested improvements

- Add a configurable time window (for example, 5 minutes)
- Add unit tests
- Support Windows Event Log and Linux authentication log exports
- Add JSON output
- Build a small dashboard
- Integrate reputable threat-intelligence feeds with appropriate API-key handling

## Responsible use

Use only logs you are authorized to analyze. Do not use this project to attempt logins against accounts or systems you do not own or have explicit permission to test.

## Skills demonstrated

Python, CSV parsing, IP validation, authentication-log analysis, basic alert severity, security reporting, and SOC investigation workflow.
