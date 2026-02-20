# IAM Least-Privilege Auditor

## Overview

This project is a read-only IAM auditing tool that identifies **over-permissive and unused permissions** across AWS IAM roles.

It combines **static policy analysis** (what permissions are granted) with **runtime usage data** (what services were actually used) to surface **real least-privilege violations**, not just generic wildcard noise.

The goal is to reduce IAM blast radius by highlighting permissions that are:

* Broad (`*`, `service:*`)
* Granted
* **Never exercised**
* Attached to **customer-managed roles**

This mirrors how IAM reviews are done in real security and cloud operations teams.

---

## What the Tool Does

For each IAM role in an AWS account, the auditor:

1. Enumerates all roles (read-only)
2. Collects:

   * Inline policies
   * Attached managed policies
3. Normalizes every policy statement into analyzable units
4. Flags:

   * Wildcard actions (`*`, `service:*`)
   * Wildcard resources (`*`)
5. Correlates permissions with **IAM service last-used data**
6. Filters out AWS-managed / service-linked role noise
7. Produces:

   * A machine-readable JSON report
   * A human-readable summary ranked by risk

---

## Why This Exists

AWS provides tools like Trusted Advisor and Access Analyzer, but they:

* Stop at best-practice checks
* Don’t correlate permissions with actual usage
* Aren’t opinionated or remediation-focused

This tool answers a more useful question:

> *“Which permissions are broad **and** have never been used?”*

That’s the core of least-privilege enforcement.

---

## Architecture (High Level)

* **Collection**: boto3 + IAM APIs
* **Analysis**: policy normalization + wildcard detection
* **Correlation**: IAM `GenerateServiceLastAccessedDetails`
* **Filtering**: AWS-managed role exclusion
* **Reporting**: risk-scored JSON + readable summary

All operations are **read-only** by design.
---
## Architecture Diagram

This diagram shows the high-level flow of the IAM Least-Privilege Auditor.

```
IAM Roles
   │
   ▼
IAM Policies (Inline + Managed)
   │
   ▼
Policy Normalization
   │
   ├── Wildcard Detection
   │
   └── Service Extraction
   │
   ▼
IAM Last-Used Service Reports
   │
   ▼
Correlation Engine
   │
   ▼
Risk Scoring
   │
   ▼
JSON Report + Human Summary
```

The auditor operates entirely in **read-only mode** and does not modify IAM resources.

---

## Screenshots

The following screenshots show the tool in action and the type of output it produces.

### CLI Execution

Demonstrates the auditor running locally and generating findings.

```
python src/auditor.py
```

**Screenshot:** `screenshots/cli-run.png`

---

### Risk Summary Output

Human-readable summary showing roles ranked by total risk score.

**Screenshot:** `screenshots/summary-output.png`

---

### JSON Findings Report

Machine-readable report used for automation, dashboards, or remediation planning.

**Screenshot:** `screenshots/json-report.png`

---

## How to Reproduce the Screenshots

1. Run the auditor from the project root:

   ```
   python src/auditor.py
   ```
2. Capture:

   * Terminal output
   * `output/summary.txt`
   * `output/report.json`
3. Save screenshots under:

   ```
   screenshots/
   ├── cli-run.png
   ├── summary-output.png
   └── json-report.png
   ```

These artifacts reflect real execution against a live AWS account.

---

## Tech Stack

* Python 3
* boto3
* AWS IAM
* IAM Access Analyzer (read-only)
* IAM last-used service reports

---

## Project Structure

```
iam-least-privilege-auditor/
├── src/
│   ├── auditor.py        # Main execution logic
│   ├── iam_collector.py  # IAM + last-used data collection
│   ├── analyzer.py       # Policy normalization & analysis
│   └── report.py         # Risk scoring & report generation
├── output/
│   ├── report.json       # Machine-readable findings
│   └── summary.txt       # Human-readable summary
├── config/
├── requirements.txt
└── README.md
```

---
## Quick Start

1. Create and activate virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate

## How It Scores Risk

Each unused permission is scored using a simple, explainable heuristic:

* Wildcard action: **+5**
* Wildcard resource: **+3**
* Service unused: **+4**
* Customer-managed role: **+2**

This produces a **relative risk ranking**, not a false sense of precision.

---

## Example Output

**summary.txt**

```
Role: cost-hygiene-ecs-task-role
Total Risk Score: 38
Findings: 5
  - ec2 | ec2:DescribeInstances | risk=9
  - cloudwatch | cloudwatch:GetMetricStatistics | risk=9
```

This highlights permissions that are safe to tighten or remove.

---

## Design Decisions

* The tool runs with **read-only IAM permissions**
* AWS-managed and service-linked roles are excluded from “unused” judgments
* IAM usage data is treated as **directional**, not absolute
* Static analysis alone is intentionally insufficient — usage matters

These choices reflect real IAM limitations and avoid false confidence.

---

## Limitations

* IAM last-used data is incomplete for some AWS service roles
* New or lightly used accounts will naturally show more unused permissions
* This tool identifies **candidates** for removal, not automatic fixes

---

## Possible Extensions

* Lambda + EventBridge scheduled execution
* Slack or email reporting
* Policy diff generation for remediation
* Age thresholds (30 / 60 / 90 days unused)
* Cross-account aggregation

---

## Why This Project Matters

IAM is one of the most misunderstood areas of AWS.

This project demonstrates:

* Deep understanding of IAM internals
* Security-first design
* Practical cloud operations thinking
* Ability to turn AWS telemetry into actionable insight

---

## Author

Built as a hands-on cloud security project to better understand IAM behavior, privilege creep, and real-world least-privilege enforcement.

