def build_response_actions(
    severity,
    attacks
):

    actions = []

    if severity == "critical":

        actions.append(
            "Block source IP"
        )

        actions.append(
            "Escalate to SOC"
        )

    if (
        "ssrf_internal_request"
        in attacks
    ):

        actions.append(
            "Block metadata service access"
        )

    if (
        "mass_assignment_role_escalation"
        in attacks
    ):

        actions.append(
            "Lock affected account"
        )

    if (
        "bola_attempt"
        in attacks
    ):

        actions.append(
            "Review employee access controls"
        )

    if (
        "employee_export"
        in attacks
    ):

        actions.append(
            "Disable export function"
        )

        actions.append(
            "Review data access logs"
        )

    return actions
