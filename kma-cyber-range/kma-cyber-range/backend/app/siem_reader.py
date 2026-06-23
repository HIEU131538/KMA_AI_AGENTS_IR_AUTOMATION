import json

ALERT_FILE = (
    "/var/log/kma-siem/alerts.json"
)

def load_siem_alerts():

    alerts = []

    try:

        with open(
            ALERT_FILE,
            "r"
        ) as f:

            for line in f.readlines():

                alerts.append(
                    json.loads(line)
                )

    except Exception:
        pass

    unique_alerts = []
    seen = set()

    for alert in alerts:

        key = (
            alert.get("rule"),
            alert.get("level")
        )

        if key not in seen:

            seen.add(key)

            unique_alerts.append(
                alert
            )

    return unique_alerts[-20:]

def alerts_to_threats(
    alerts
):

    threats = []

    for alert in alerts:

        rule = alert.get(
            "rule"
        )

        if (
            rule
            ==
            "Privilege Escalation"
        ):

            threats.append({
                "attack":
                    "privilege_escalation",

                "mitre":
                    "T1078"
            })

        elif (
            rule
            ==
            "SSRF Attempt"
        ):

            threats.append({
                "attack":
                    "ssrf_internal_request",

                "mitre":
                    "T1190"
            })

        elif (
            rule
            ==
            "Data Exfiltration"
        ):

            threats.append({
                "attack":
                    "employee_export",

                "mitre":
                    "TA0010"
            })

    return threats
