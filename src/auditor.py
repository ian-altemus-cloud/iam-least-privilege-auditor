from iam_collector import collect_iam_data
from analyzer import normalize_statements
from report import build_report, write_json_report, write_summary


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

    for role in iam_data:
        role_name = role["role_name"]

        if is_aws_managed_role(role_name):
            continue

        used_services = build_last_used_service_set(
            role.get("last_used_services", [])
        )

        role_findings = []

        for policy_name, doc in role["inline_policies"].items():
            role_findings.extend(
                normalize_statements(role_name, policy_name, doc)
            )

        for policy_name, doc in role["managed_policies"].items():
            role_findings.extend(
                normalize_statements(role_name, policy_name, doc)
            )

        for finding in role_findings:
            service = finding["service"]

            if (
                finding["flags"]
                and service != "*"
                and service not in used_services
            ):
                unused_dangerous.append(finding)

    report = build_report(unused_dangerous)
    write_json_report(report)
    write_summary(report)

    print(f"Roles flagged: {len(report)}")
    print("Reports written to output/")

    top = sorted(
        report.items(),
        key=lambda x: x[1]["total_risk"],
        reverse=True
    )[:3]

    print("\nTop risky roles:")
    for role, data in top:
        print(f"- {role}: risk={data['total_risk']}")


if __name__ == "__main__":
    main()

