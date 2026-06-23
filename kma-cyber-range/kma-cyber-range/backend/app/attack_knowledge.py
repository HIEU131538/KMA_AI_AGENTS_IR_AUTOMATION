ATTACK_PHASES = {

    1: {
        "name": "Request Smuggling",
        "indicators": [
            "request_smuggling",
            "cl_te_conflict",
            "te_cl_conflict"
        ]
    },

    2: {
        "name": "SSRF",
        "indicators": [
            "ssrf_metadata_request",
            "ssrf_internal_request"
        ]
    },

    3: {
        "name": "Privilege Escalation",
        "indicators": [
            "mass_assignment_role_escalation",
            "privilege_escalation"
        ]
    },

    4: {
        "name": "JWT Abuse",
        "indicators": [
            "jwt_abuse",
            "jwt_token_reuse"
        ]
    },

    5: {
        "name": "Data Exfiltration",
        "indicators": [
            "bulk_export",
            "employee_export"
        ]
    }
}
