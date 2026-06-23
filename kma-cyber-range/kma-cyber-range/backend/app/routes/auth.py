from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.security_logger import write_auth_event
from app.security_event_service import write_security_event

from app.database import get_db
from app.models import RevokedToken, User
from app.schemas import (
    Fido2LoginRequest,
    Fido2RegisterRequest,
    LoginRequest,
    WebAuthnFinishRequest,
    WebAuthnLoginStartRequest,
)
from app.security import (
    create_access_token,
    extract_token,
    get_current_user,
    unsafe_get_claims,
    verify_password,
)
from app.fido2.webauthn_service import (
    generate_login_options,
    generate_register_options,
    verify_and_store_registration,
    verify_login_response,
)

router = APIRouter(tags=["Auth"])


@router.post("/auth/login")
def login(
    data: LoginRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == data.username).first()

    if not user:
        request.state.detected_attack = "login_failed"
        request.state.security_message = f"Login failed: user not found: {data.username}"

        write_auth_event(
            event="login_failed",
            actor=data.username,
            result="user_not_found",
            ip=request.client.host,
            severity="low"
        )

        write_security_event(
            event="user_login_failed",
            severity="medium",
            user=data.username,
            ip=request.client.host,
            details="user_not_found"
        )

        raise HTTPException(
                status_code=401,
                detail="Invalid username or password"
        )

    if not user.is_active:
        request.state.detected_attack = "disabled_user_login"
        request.state.security_message = f"Disabled user tried to login: {data.username}"

        write_auth_event(
            event="login_failed",
            actor=data.username,
            result="disabled_user",
            ip=request.client.host
        )

        raise HTTPException(
                status_code=403,
                detail="User is disabled"
        )

    if not verify_password(data.password, user.hashed_password):
        request.state.detected_attack = "login_failed"
        request.state.security_message = (
                f"Login failed: wrong password for {data.username}"
        )

        write_auth_event(
            event="login_failed",
            actor=data.username,
            result="wrong_password",
            ip=request.client.host,
            severity="low"
        )

        write_security_event(
            event="user_login_failed",
            severity="medium",
            user=data.username,
            ip=request.client.host,
            details="wrong_password"
        )

        raise HTTPException(
                status_code=401,
                detail="Invalid username or password"
        )

    token = create_access_token(user)

    request.state.user_id = user.id
    request.state.username = user.username
    request.state.role = user.role
    request.state.detected_attack = "login_success"
    request.state.security_message = "User logged in successfully"

    write_auth_event(
        event="login_success",
        actor=user.username,
        result="success",
        ip=request.client.host,
        severity="info"
    )

    write_security_event(
        event="user_login_success",
        severity="low",
        user=user.username,
        ip=request.client.host
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "role": user.role
        }
    }


@router.get("/auth/session/validate")
def validate_session(
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    request.state.user_id = current_user["id"]
    request.state.username = current_user["username"]
    request.state.role = current_user["role"]
    request.state.jti = current_user["jti"]
    request.state.detected_attack = "jwt_validate"
    request.state.security_message = "JWT session validated successfully"

    return {
        "valid": True,
        "user": {
            "id": current_user["id"],
            "username": current_user["username"],
            "role": current_user["role"]
        },
        "jti": current_user["jti"]
    }


@router.get("/auth/session/validate-lab")
def validate_session_lab(
    request: Request,
    authorization: Optional[str] = Header(default=None)
):
    claims = unsafe_get_claims(authorization)

    request.state.username = claims.get("sub")
    request.state.role = claims.get("role")
    request.state.detected_attack = "jwt_unverified_validation"
    request.state.mitre_technique = "T1550.004"
    request.state.security_message = "JWT payload parsed without signature verification"

    return {
        "valid": True,
        "claims": claims,
        "warning": "Lab mode: JWT signature is NOT verified here. This endpoint is intentionally vulnerable."
    }


@router.post("/auth/logout")
def logout(
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    jti = current_user["jti"]

    existing = db.query(RevokedToken).filter(RevokedToken.jti == jti).first()

    if not existing:
        revoked = RevokedToken(
            jti=jti,
            username=current_user["username"]
        )

        db.add(revoked)
        db.commit()

    request.state.user_id = current_user["id"]
    request.state.username = current_user["username"]
    request.state.role = current_user["role"]
    request.state.jti = current_user["jti"]
    request.state.detected_attack = "logout"
    request.state.security_message = "User logged out and token revoked"

    return {
        "message": "Logout successful",
        "revoked_jti": jti
    }


@router.post("/auth/fido2/register/start")
def fido2_register_start(
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == current_user["id"]).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    options = generate_register_options(db, user)

    request.state.user_id = user.id
    request.state.username = user.username
    request.state.role = user.role
    request.state.jti = current_user.get("jti")
    request.state.security_message = "FIDO2 registration challenge generated"

    return options


@router.post("/auth/fido2/register/finish")
def fido2_register_finish(
    data: WebAuthnFinishRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == current_user["id"]).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    stored = verify_and_store_registration(
        db=db,
        user=user,
        credential=data.credential,
    )

    request.state.user_id = user.id
    request.state.username = user.username
    request.state.role = user.role
    request.state.jti = current_user.get("jti")
    request.state.security_message = "FIDO2 credential registered successfully"

    return {
        "verified": True,
        "message": "FIDO2 credential registered successfully",
        "credential": {
            "id": stored.id,
            "credential_id": stored.credential_id,
            "sign_count": stored.sign_count,
        }
    }


@router.post("/auth/fido2/login/start")
def fido2_login_start(
    data: WebAuthnLoginStartRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    options = generate_login_options(db, data.username)

    request.state.username = data.username
    request.state.security_message = "FIDO2 authentication challenge generated"

    return options


@router.post("/auth/fido2/login/finish")
def fido2_login_finish(
    data: WebAuthnFinishRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    user = verify_login_response(db=db, credential=data.credential)

    token = create_access_token(user)

    request.state.user_id = user.id
    request.state.username = user.username
    request.state.role = user.role
    request.state.security_message = "FIDO2 login verified and JWT issued"

    return {
        "verified": True,
        "message": "FIDO2 login successful",
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "role": user.role,
        }
    }
