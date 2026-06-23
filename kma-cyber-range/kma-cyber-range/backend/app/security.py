import os
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import Depends, Header, HTTPException
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import RevokedToken, User

load_dotenv("/app/backend/.env")

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev_secret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    if not hashed_password:
        return False

    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(user: User) -> str:
    payload = {
        "sub": user.username,
        "role": user.role,
        "user_id": user.id,
        "jti": str(uuid4()),
        "exp": datetime.utcnow() + timedelta(hours=2)
    }

    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def extract_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None

    if not authorization.lower().startswith("bearer "):
        return None

    return authorization.split(" ", 1)[1].strip()


def decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM]
        )
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def verify_access_token(authorization: Optional[str] = Header(default=None)) -> dict:
    token = extract_token(authorization)

    if not token:
        raise HTTPException(status_code=401, detail="Missing bearer token")

    return decode_access_token(token)


def get_current_user(
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db)
) -> dict:
    token = extract_token(authorization)

    if not token:
        raise HTTPException(status_code=401, detail="Missing bearer token")

    payload = decode_access_token(token)

    username = payload.get("sub")
    role = payload.get("role")
    user_id = payload.get("user_id")
    jti = payload.get("jti")

    if not username or not role or not jti:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    revoked = db.query(RevokedToken).filter(RevokedToken.jti == jti).first()

    if revoked:
        raise HTTPException(status_code=401, detail="Token has been revoked")

    user = db.query(User).filter(User.username == username).first()

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User is disabled")

    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "jti": jti,
        "claims": payload
    }


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin privilege required")

    return current_user


def require_roles(allowed_roles: list[str]):
    def dependency(current_user: dict = Depends(get_current_user)) -> dict:
        if current_user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied. Required roles: {allowed_roles}"
            )

        return current_user

    return dependency


def unsafe_get_claims(authorization: Optional[str]) -> dict:
    token = extract_token(authorization)

    if not token:
        return {
            "sub": "anonymous",
            "role": "guest",
            "jti": "none"
        }

    try:
        return jwt.get_unverified_claims(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token format")
