import boto3
import time

iam = boto3.client("iam")


def get_all_roles():
    roles = []
    paginator = iam.get_paginator("list_roles")

    for page in paginator.paginate():
        roles.extend(page["Roles"])

    return roles


def get_inline_policies(role_name):
    policies = {}

    response = iam.list_role_policies(RoleName=role_name)

    for policy_name in response["PolicyNames"]:
        policy = iam.get_role_policy(
            RoleName=role_name,
            PolicyName=policy_name
        )
        policies[policy_name] = policy["PolicyDocument"]

    return policies


def get_managed_policies(role_name):
    policies = {}

    response = iam.list_attached_role_policies(RoleName=role_name)

    for policy in response["AttachedPolicies"]:
        policy_arn = policy["PolicyArn"]

        policy_meta = iam.get_policy(PolicyArn=policy_arn)
        default_version = policy_meta["Policy"]["DefaultVersionId"]

        version = iam.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=default_version
        )

        policies[policy["PolicyName"]] = version["PolicyVersion"]["Document"]

    return policies


def get_last_used_services(role_arn):
    job = iam.generate_service_last_accessed_details(
        Arn=role_arn
    )

    job_id = job["JobId"]

    while True:
        response = iam.get_service_last_accessed_details(
            JobId=job_id
        )

        if response["JobStatus"] == "COMPLETED":
            return response["ServicesLastAccessed"]

        time.sleep(1)


def collect_iam_data():
    data = []
    roles = get_all_roles()

    for role in roles:
        role_name = role["RoleName"]
        role_arn = role["Arn"]

        last_used_services = get_last_used_services(role_arn)

        data.append({
            "role_name": role_name,
            "arn": role_arn,
            "last_used": role.get("RoleLastUsed", {}).get("LastUsedDate"),
            "last_used_services": last_used_services,
            "inline_policies": get_inline_policies(role_name),
            "managed_policies": get_managed_policies(role_name)
        })

    return data

