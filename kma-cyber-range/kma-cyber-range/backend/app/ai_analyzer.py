from app.phase_detector import (
    detect_attack_phase
)

from app.response_engine import (
    build_response_actions
)

from app.jwt_detector import (
    detect_jwt_abuse
)

from app.exfil_detector import (
    detect_data_exfiltration
)

from app.correlation_engine import (
    build_attack_timeline,
    build_incident_summary,
    build_attacker_profile
)

def calculate_severity(threats):

    attacks = [x.get("attack") for x in threats]

    if "employee_export" in attacks:
       return "critical"

    critical_attacks = {
        "ssrf_internal_request",
        "bola_attempt",
        "mass_assignment_role_escalation"
    }

    if "ssrf_metadata_request" in attacks:
        return "critical"

    if len(
        critical_attacks.intersection(
            set(attacks)
        )
    ) >= 2:
        return "critical"

    if "jwt_abuse" in attacks:
        return "high"

    if (
        "mass_assignment_role_escalation" in attacks
        or
        "bola_attempt" in attacks
        or
        "ssrf_internal_request" in attacks
    ):
        return "high"

    if len(attacks) > 0:
        return "medium"

    return "low"

def build_attack_chain(events, threats):

    chain = []

    for event in events:

        if event.get("event"):
            chain.append(event["event"])

    for threat in threats:

        if threat.get("attack"):
            chain.append(threat["attack"])

    chain = list(dict.fromkeys(chain))

    return chain[-10:]

def build_mitre_mapping(threats):

    mitres = set()

    for threat in threats:

        if threat.get("mitre"):
            mitres.add(threat["mitre"])

    return sorted(list(mitres))

def build_recommendations(threats):

    recommendations = []

    attacks = [x.get("attack") for x in threats]

    if "mass_assignment_role_escalation" in attacks:
        recommendations.append(
            "Review role changes"
        )

    if "bola_attempt" in attacks:
        recommendations.append(
            "Review employee access controls"
        )

    if "ssrf_internal_request" in attacks:
        recommendations.append(
            "Inspect SSRF activity"
        )

    if "ssrf_metadata_request" in attacks:
        recommendations.append(
            "Block metadata service access"
        )

    recommendations.append(
        "Review WAF alerts"
    )

    if "jwt_abuse" in attacks:

        recommendations.append(
            "Invalidate suspicious JWT tokens"
        )

        recommendations.append(
            "Review login locations"
        )

    if "employee_export" in attacks:

        recommendations.append(
            "Review employee data access"
        )

        recommendations.append(
            "Check bulk export activity"
        )

    return recommendations

def analyze_security(events, threats):

    if detect_jwt_abuse(events):

       threats.append({
           "attack": "jwt_abuse",
           "mitre": "T1078"
       })

    if detect_data_exfiltration(events):

       threats.append({
           "attack": "employee_export",
           "mitre": "TA0010"
       })

    phase = detect_attack_phase(
        threats
    )

    attacks = [
        x.get("attack")
        for x in threats
    ]

    return {

        "attack_chain":
            build_attack_chain(
                events,
                threats
            ),

        "severity":
            calculate_severity(
                threats
            ),

        "timeline":
            build_attack_timeline(
                events,
                threats
            ),

        "summary":
            build_incident_summary(
                build_attack_chain(
                    events,
                    threats
                ),
                calculate_severity(
                    threats
                )
            ),

        "profile":
            build_attacker_profile(
                threats
            ),

        "mitre":
            build_mitre_mapping(
                threats
            ),

        "recommendations":
            build_recommendations(
                threats
            ),

        "phase":
            phase,

        "response_actions":
            build_response_actions(
                calculate_severity(
                    threats
                ),
                attacks
            )
    }
