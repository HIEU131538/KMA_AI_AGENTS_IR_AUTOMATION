def generate_registration_options(username: str):
    """
    Placeholder cho FIDO2/WebAuthn registration.
    Phase sau sẽ thay bằng PyWebAuthn thật.
    """

    return {
        "username": username,
        "challenge": "demo-register-challenge",
        "rp_name": "KMA HR Management",
        "rp_id": "localhost"
    }
