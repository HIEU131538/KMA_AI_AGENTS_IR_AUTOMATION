from collections import defaultdict

def detect_jwt_abuse(events):

    token_ips = defaultdict(set)

    for event in events:

        auth = event.get(
            "auth_context",
            {}
        )

        jti = auth.get("jti")

        ip = event.get(
            "client_ip"
        )

        if jti and ip:

            token_ips[jti].add(ip)

    for ips in token_ips.values():

        if len(ips) >= 5:
            return True

    return False
