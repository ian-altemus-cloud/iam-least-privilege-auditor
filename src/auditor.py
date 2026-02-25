from iam_collector import collect_iam_data
from analyzer import normalize_statements
from report import build_report, write_json_report, write_summary, write_markdown_report
from ai_enricher import enrich_finding
import boto3

def build_last_used_service_set(last_used_services):
    used = set()
    for svc in last_used_services:
        if svc.get("LastAuthenticated"):
            used.add(svc["ServiceName"].lower())
    return used


def is_aws_managed_role(role_name):
    return (
        role_name.startswith("AWSServiceRoleFor")
        or role_name.startswith("aws-")
    )


def main():
    iam_data = collect_iam_data()

    unused_dangerous = []

    # -------- Deterministic IAM Analysis --------
    for role in iam_data:
        role_name = role["role_name"]

        if is_aws_managed_role(role_name):
            continue

        used_services = build_last_used_service_set(
            role.get("last_used_services", [])
        )

        role_findings = []

        # Inline policies
        for policy_name, doc in role["inline_policies"].items():
            role_findings.extend(
                normalize_statements(role_name, policy_name, doc)
            )

        # Managed policies
        for policy_name, doc in role["managed_policies"].items():
            role_findings.extend(
                normalize_statements(role_name, policy_name, doc)
            )

        # Filter unused + dangerous
        for finding in role_findings:
            service = finding["service"]

            if (
                finding["flags"]
                and service != "*"
                and service not in used_services
            ):
                unused_dangerous.append(finding)

    print(f"Total unused + dangerous findings: {len(unused_dangerous)}")

    # -------- Deterministic Report --------
    report = build_report(unused_dangerous)
    write_json_report(report, "output/report.json")
    write_summary(report)

    # -------- AI Enrichment Layer --------
    enriched = []

    # Limit to first 10 findings for cost control
    for finding in unused_dangerous[:10]:
        try:
            enriched.append(enrich_finding(finding))
        except Exception as e:
            print(f"AI enrichment failed for finding: {finding}")
            print(str(e))

    write_json_report(enriched, "output/enriched_findings.json")

    write_markdown_report(enriched)

    print(f"Roles flagged: {len(report)}")
    print("AI-enriched report written to output/enriched_findings.json")


if __name__ == "__main__":
    main()
