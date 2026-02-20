def extract_service(action):
    if action == "*":
        return "*"
    return action.split(":")[0]


def normalize_statements(role_name, policy_name, policy_doc):
    findings = []

    statements = policy_doc.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        effect = stmt.get("Effect")
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])

        if not isinstance(actions, list):
            actions = [actions]
        if not isinstance(resources, list):
            resources = [resources]

        for action in actions:
            for resource in resources:
                flags = []

                service = extract_service(action)

                if action == "*" or action.endswith(":*"):
                    flags.append("WILDCARD_ACTION")

                if resource == "*":
                    flags.append("WILDCARD_RESOURCE")

                findings.append({
                    "role": role_name,
                    "policy": policy_name,
                    "effect": effect,
                    "service": service,
                    "action": action,
                    "resource": resource,
                    "flags": flags
                })

    return findings

