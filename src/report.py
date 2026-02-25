import json
from collections import defaultdict


def calculate_risk(finding):
    score = 0

    if "WILDCARD_ACTION" in finding["flags"]:
        score += 5

    if "WILDCARD_RESOURCE" in finding["flags"]:
        score += 3

    score += 4  # unused service (already filtered)

    score += 2  # custom role

    return score


def build_report(unused_findings):
    report = defaultdict(lambda: {
        "total_risk": 0,
        "findings": []
    })

    for finding in unused_findings:
        role = finding["role"]
        risk = calculate_risk(finding)

        finding_entry = {
            "service": finding["service"],
            "action": finding["action"],
            "resource": finding["resource"],
            "flags": finding["flags"],
            "risk_score": risk
        }

        report[role]["findings"].append(finding_entry)
        report[role]["total_risk"] += risk

    return report


def write_json_report(report, path="output/report.json"):
    with open(path, "w") as f:
        json.dump(report, f, indent=2)


def write_summary(report, path="output/summary.txt"):
    sorted_roles = sorted(
        report.items(),
        key=lambda x: x[1]["total_risk"],
        reverse=True
    )

    with open(path, "w") as f:
        for role, data in sorted_roles:
            f.write(f"Role: {role}\n")
            f.write(f"Total Risk Score: {data['total_risk']}\n")
            f.write(f"Findings: {len(data['findings'])}\n")

            for finding in data["findings"]:
                f.write(
                    f"  - {finding['service']} | "
                    f"{finding['action']} | "
                    f"risk={finding['risk_score']}\n"
                )

            f.write("\n")

def write_markdown_report(enriched_findings, filepath="output/REPORT.md"):
    with open(filepath, "w") as f:
        f.write("# IAM Least Privilege Audit Report\n\n")

        for finding in enriched_findings:
            ai = finding.get("ai_analysis", {})

            f.write(f"## Role: {finding['role']}\n")
            f.write(f"**Policy:** {finding['policy']}\n")
            f.write(f"**Permission:** `{finding['action']}` on `{finding['resource']}`\n")
            f.write(f"**Service:** {finding['service']}\n")
            f.write(f"**Risk Level:** {ai.get('risk_level', 'N/A').upper()}\n\n")

            f.write("### What This Means\n")
            f.write(ai.get("explanation", "N/A") + "\n\n")

            f.write("### Abuse Scenario\n")
            f.write(ai.get("abuse_scenario", "N/A") + "\n\n")

            f.write("### Recommended Remediation\n")
            for rec in ai.get("remediation_recommendations", []):
                f.write(f"- {rec}\n")

            f.write("\n---\n\n")
