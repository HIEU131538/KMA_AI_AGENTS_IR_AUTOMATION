def build_attack_timeline(
    events,
    threats
):

    timeline = []

    for event in events:

        if not event.get("timestamp"):
            continue

        timeline.append({
            "timestamp":
                event.get("timestamp"),

            "type":
                "event",

            "name":
                event.get("event")
        })

    for threat in threats:

        if not threat.get("timestamp"):
            continue

        timeline.append({
            "timestamp":
                threat.get("timestamp"),

            "type":
                "threat",

            "name":
                threat.get("attack")
        })

    timeline.sort(
        key=lambda x:
            x.get(
                "timestamp",
                ""
            )
    )

    return timeline[-20:]

def build_incident_summary(
    attack_chain,
    severity
):

    if not attack_chain:

        return (
            "No active attack detected."
        )

    return (
        f"Multi-stage attack "
        f"detected with "
        f"{len(attack_chain)} "
        f"attack steps. "
        f"Current severity: "
        f"{severity.upper()}."
    )

def build_attacker_profile(
    threats
):

    attacks = [
        x.get("attack")
        for x in threats
    ]

    if (
        "employee_export"
        in attacks
    ):
        return (
            "Data Theft Activity"
        )

    if (
        "mass_assignment_role_escalation"
        in attacks
    ):
        return (
            "Privilege Escalation Attempt"
        )

    if (
        "ssrf_internal_request"
        in attacks
    ):
        return (
            "Internal Reconnaissance"
        )

    return (
        "Unknown Activity"
    )
