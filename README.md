# IAM Least-Privilege Auditor

## Overview

IAM Least-Privilege Auditor is a read-only AWS security analysis tool that identifies **over-permissive and unused IAM role permissions**.

It combines deterministic policy analysis with AWS service last-used telemetry to detect real least-privilege violations. An optional AI enrichment layer generates contextual explanations and remediation guidance in executive-readable format.

The core detection engine is deterministic and security-first. AI is used only to enhance interpretation — never to replace policy analysis.

---

## What the Tool Does

For each IAM role in an AWS account, the auditor:

1. Enumerates roles (read-only)
2. Collects:

   * Inline policies
   * Attached managed policies
3. Normalizes policy statements
4. Detects:

   * Wildcard actions (`*`, `service:*`)
   * Wildcard resources (`*`)
5. Correlates permissions with IAM service last-used data
6. Excludes AWS-managed / service-linked roles
7. Produces:

   * `report.json` (machine-readable findings)
   * `summary.txt` (risk-ranked summary)
   * `enriched_findings.json` (AI-enhanced findings)
   * `REPORT.md` (human-readable executive report)

All operations are strictly read-only.

---

## Architecture

**Layer 1 – Deterministic Analysis**

* IAM role enumeration
* Policy normalization
* Wildcard detection
* Last-used service correlation
* Risk scoring

**Layer 2 – AI Enrichment (Optional)**

* Plain-English explanation
* Realistic abuse scenario
* Risk classification
* Remediation recommendations
* Markdown executive reporting

The AI layer enhances interpretation but does not influence detection logic.

---

## Example Executive Output

### Role: cost-guardian-lambda-role

**Permission:** `ec2:Describe*`
**Risk Level:** MEDIUM

**What This Means**
This role can retrieve information about all EC2 resources in the account, including instances, volumes, and security groups.

**Abuse Scenario**
An attacker could enumerate infrastructure, identify attack surfaces, and prepare for lateral movement.

**Recommended Remediation**

* Restrict to required Describe actions only
* Limit scope where possible
* Monitor usage patterns

---

## Project Structure

```
iam-least-privilege-auditor/
├── src/
│   ├── auditor.py
│   ├── iam_collector.py
│   ├── analyzer.py
│   ├── report.py
│   └── ai_enricher.py
├── output/
│   ├── report.json
│   ├── summary.txt
│   ├── enriched_findings.json
│   └── REPORT.md
├── requirements.txt
└── README.md
```

---

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Ensure AWS credentials are configured with read-only IAM permissions.

Run:

```bash
python src/auditor.py
```

If using AI enrichment, set:

```bash
export OPENAI_API_KEY="your-api-key"
```

---

## Risk Scoring Model

Each finding is ranked using a simple heuristic:

* Wildcard action: +5
* Wildcard resource: +3
* Service unused: +4
* Customer-managed role: +2

This produces relative prioritization, not artificial precision.

---

## Design Principles

* Read-only by design
* Deterministic detection first
* AI used for interpretation only
* Cost-controlled AI calls
* Separation of machine and executive outputs
* Avoid false confidence in telemetry data

---

## Why This Project Matters

IAM is one of the most misunderstood areas of AWS.

This project demonstrates:

* Deep IAM policy understanding
* Security-first cloud thinking
* Practical use of AWS telemetry
* AI augmentation without sacrificing deterministic controls
* Clean separation between analysis and reporting layers

---

## Positioning

This tool reflects the mindset of a cloud engineer who understands that:

* Infrastructure security requires precision
* Telemetry must be interpreted carefully
* Automation should enhance clarity, not introduce risk

---

Built as part of a broader cloud automation and security portfolio including cost governance and serverless event-driven systems.

