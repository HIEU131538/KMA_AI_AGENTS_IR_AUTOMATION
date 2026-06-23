def generate_authentication_options(username: str):
    """
    Placeholder cho FIDO2/WebAuthn authentication.
    Phase sau sẽ thay bằng PyWebAuthn thật.
    """

    return {
        "username": username,
        "challenge": "demo-login-challenge",
        "rp_id": "localhost"
    }
