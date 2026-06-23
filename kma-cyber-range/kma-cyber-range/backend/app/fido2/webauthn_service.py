import base64
import json
import os
from typing import Any

from dotenv import load_dotenv
from fastapi import HTTPException
from sqlalchemy.orm import Session

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.models import User, WebAuthnCredential

load_dotenv("/app/backend/.env")


# Lab-only challenge store.
# Production nên dùng Redis/DB có TTL, không dùng memory dict.
REGISTRATION_CHALLENGES: dict[str, bytes] = {}
AUTHENTICATION_CHALLENGES: dict[str, bytes] = {}


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def get_rp_id() -> str:
    return os.getenv("WEBAUTHN_RP_ID", "localhost")


def get_rp_name() -> str:
    return os.getenv("WEBAUTHN_RP_NAME", "KMA HR Management")


def get_expected_origin() -> str:
    return os.getenv("WEBAUTHN_EXPECTED_ORIGIN", "http://localhost:3000")


def require_user_verification() -> bool:
    return os.getenv("WEBAUTHN_REQUIRE_USER_VERIFICATION", "true").lower() == "true"


def options_to_dict(options: Any) -> dict:
    return json.loads(options_to_json(options))


def get_user_credentials(db: Session, user_id: int) -> list[WebAuthnCredential]:
    return (
        db.query(WebAuthnCredential)
        .filter(WebAuthnCredential.user_id == user_id)
        .all()
    )


def generate_register_options(db: Session, user: User) -> dict:
    existing_credentials = get_user_credentials(db, user.id)

    exclude_credentials = [
        PublicKeyCredentialDescriptor(id=b64url_decode(item.credential_id))
        for item in existing_credentials
    ]

    options = generate_registration_options(
        rp_id=get_rp_id(),
        rp_name=get_rp_name(),
        user_id=str(user.id).encode("utf-8"),
        user_name=user.username,
        user_display_name=user.username,
        exclude_credentials=exclude_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )

    REGISTRATION_CHALLENGES[user.username] = options.challenge

    return options_to_dict(options)


def verify_and_store_registration(
    db: Session,
    user: User,
    credential: dict,
) -> WebAuthnCredential:
    challenge = REGISTRATION_CHALLENGES.get(user.username)

    if not challenge:
        raise HTTPException(
            status_code=400,
            detail="Registration challenge not found or expired"
        )

    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=get_expected_origin(),
            expected_rp_id=get_rp_id(),
            require_user_verification=require_user_verification(),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"WebAuthn registration verification failed: {str(exc)}"
        )

    credential_id = b64url_encode(verification.credential_id)
    public_key = b64url_encode(verification.credential_public_key)

    existing = (
        db.query(WebAuthnCredential)
        .filter(WebAuthnCredential.credential_id == credential_id)
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=409,
            detail="This authenticator is already registered"
        )

    stored = WebAuthnCredential(
        user_id=user.id,
        credential_id=credential_id,
        public_key=public_key,
        sign_count=verification.sign_count,
    )

    db.add(stored)
    db.commit()
    db.refresh(stored)

    REGISTRATION_CHALLENGES.pop(user.username, None)

    return stored


def generate_login_options(db: Session, username: str) -> dict:
    user = db.query(User).filter(User.username == username).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    credentials = get_user_credentials(db, user.id)

    if not credentials:
        raise HTTPException(
            status_code=404,
            detail="No WebAuthn credential registered for this user"
        )

    allow_credentials = [
        PublicKeyCredentialDescriptor(id=b64url_decode(item.credential_id))
        for item in credentials
    ]

    options = generate_authentication_options(
        rp_id=get_rp_id(),
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    AUTHENTICATION_CHALLENGES[user.username] = options.challenge

    return options_to_dict(options)


def verify_login_response(db: Session, credential: dict) -> User:
    credential_id = credential.get("id")

    if not credential_id:
        raise HTTPException(status_code=400, detail="Credential id is missing")

    stored = (
        db.query(WebAuthnCredential)
        .filter(WebAuthnCredential.credential_id == credential_id)
        .first()
    )

    if not stored:
        raise HTTPException(status_code=404, detail="Credential not registered")

    user = db.query(User).filter(User.id == stored.user_id).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    challenge = AUTHENTICATION_CHALLENGES.get(user.username)

    if not challenge:
        raise HTTPException(
            status_code=400,
            detail="Authentication challenge not found or expired"
        )

    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=get_rp_id(),
            expected_origin=get_expected_origin(),
            credential_public_key=b64url_decode(stored.public_key),
            credential_current_sign_count=stored.sign_count,
            require_user_verification=require_user_verification(),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"WebAuthn authentication verification failed: {str(exc)}"
        )

    stored.sign_count = verification.new_sign_count
    db.commit()

    AUTHENTICATION_CHALLENGES.pop(user.username, None)

    return user
