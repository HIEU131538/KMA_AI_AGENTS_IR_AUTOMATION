import json
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import APIRouter, Header, HTTPException, Query, Request
from jose import jwt
from pydantic import BaseModel


load_dotenv("/app/backend/.env")

router = APIRouter()

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev_secret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
LOG_PATH = "/var/log/kma-app/app.log"


# =========================
# Models
# =========================

class Fido2RegisterRequest(BaseModel):
    username: str


class Fido2LoginRequest(BaseModel):
    username: str


class ProfileUpdateRequest(BaseModel):
    full_name: Optional[str] = None
    phone: Optional[str] = None
    department: Optional[str] = None
    role: Optional[str] = None


class RebootServiceRequest(BaseModel):
    service_name: str
    reason: Optional[str] = None
    command: Optional[str] = None


# =========================
# Helper functions
# =========================

def extract_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None

    if not authorization.lower().startswith("bearer "):
        return None

    return authorization.split(" ", 1)[1].strip()


def issue_token(username: str, role: str):
    payload = {
        "sub": username,
        "role": role,
        "jti": f"token-{username}-{int(time.time())}",
        "exp": datetime.utcnow() + timedelta(hours=2)
    }

    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def unsafe_get_claims(authorization: Optional[str]):
    """
    Lab intentionally vulnerable behavior:
    Hàm này đọc JWT payload mà không verify chữ ký.
    Chỉ dùng trong Cyber Range để minh họa JWT Forgery.
    """
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


# =========================
# 1. IAM / FIDO2 / Session
# =========================

@router.post("/auth/fido2/register")
def fido2_register(data: Fido2RegisterRequest, request: Request):
    """
    Skeleton endpoint cho FIDO2 register.

    Phase hiện tại:
    - Chưa verify WebAuthn thật.
    - Chỉ tạo endpoint để thống nhất API contract.
    - Sau này thay bằng py_webauthn/simplewebauthn flow.
    """

    request.state.detected_attack = "none"
    request.state.mitre_technique = None
    request.state.security_message = "FIDO2 register endpoint called"

    return {
        "message": "FIDO2 registration challenge generated",
        "username": data.username,
        "challenge": "demo-register-challenge",
        "note": "This is a placeholder. Real WebAuthn verification will be implemented later."
    }


@router.post("/auth/fido2/login")
def fido2_login(data: Fido2LoginRequest, request: Request):
    """
    Skeleton endpoint cho FIDO2 login.

    Phase hiện tại:
    - Mô phỏng xác thực passkey thành công.
    - Trả về JWT để frontend/API dùng tiếp.
    """

    role = "admin" if data.username == "admin" else "employee"
    token = issue_token(data.username, role)

    request.state.detected_attack = "none"
    request.state.mitre_technique = None
    request.state.security_message = "FIDO2 login simulated successfully"

    return {
        "message": "FIDO2 login successful",
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "username": data.username,
            "role": role
        }
    }


@router.get("/auth/session/validate")
def validate_session(request: Request, authorization: Optional[str] = Header(default=None)):
    """
    Lab vulnerability:
    Cố tình đọc JWT payload mà không verify chữ ký để mô phỏng JWT Forgery.
    """

    claims = unsafe_get_claims(authorization)

    request.state.detected_attack = "jwt_unverified_validation"
    request.state.mitre_technique = "T1550.004"
    request.state.security_message = "JWT payload parsed without signature verification"

    return {
        "valid": True,
        "claims": claims,
        "warning": "Lab mode: JWT signature is not strictly verified here."
    }


@router.post("/auth/logout")
def logout(request: Request, authorization: Optional[str] = Header(default=None)):
    token = extract_token(authorization)

    request.state.detected_attack = "none"
    request.state.security_message = "Logout endpoint called"

    return {
        "message": "Logout successful",
        "revoked_token": token[:20] + "..." if token else None
    }


# =========================
# 2. Core HR Logic
# =========================

@router.get("/api/v1/employees/me")
def get_my_profile(request: Request, authorization: Optional[str] = Header(default=None)):
    claims = unsafe_get_claims(authorization)

    request.state.detected_attack = "none"
    request.state.mitre_technique = "T1082"
    request.state.security_message = "Current user profile requested"

    return {
        "id": 2,
        "username": claims.get("sub", "employee01"),
        "role": claims.get("role", "employee"),
        "full_name": "Tran Thi B",
        "department": "HR",
        "salary": 20000000,
        "phone": "0900000002"
    }


@router.patch("/api/v1/employees/profile")
def update_profile(
    data: ProfileUpdateRequest,
    request: Request,
    authorization: Optional[str] = Header(default=None)
):
    """
    Lab vulnerability:
    Mass Assignment - cố tình cho phép client gửi field role.
    """

    claims = unsafe_get_claims(authorization)

    updated_profile = {
        "username": claims.get("sub", "employee01"),
        "full_name": data.full_name or "Tran Thi B",
        "phone": data.phone or "0900000002",
        "department": data.department or "HR",
        "role": data.role or claims.get("role", "employee")
    }

    if data.role == "admin":
        request.state.detected_attack = "mass_assignment_role_escalation"
        request.state.mitre_technique = "T1078"
        request.state.security_message = "Mass Assignment attempt: role field modified to admin"
    else:
        request.state.detected_attack = "none"
        request.state.security_message = "Profile updated"

    return {
        "message": "Profile updated",
        "profile": updated_profile,
        "lab_note": "This endpoint intentionally accepts role field for Mass Assignment demonstration."
    }


@router.get("/api/v1/departments")
def list_departments(request: Request):
    request.state.detected_attack = "none"
    request.state.security_message = "Departments listed"

    return {
        "departments": [
            {"id": 1, "name": "Board"},
            {"id": 2, "name": "Human Resources"},
            {"id": 3, "name": "Information Technology"},
            {"id": 4, "name": "Security Operations"}
        ]
    }


# =========================
# 3. Tools / Vulnerability Gateway
# =========================

@router.get("/api/v1/tools/fetch-external")
def fetch_external(
    request: Request,
    url: str = Query(..., description="External URL to fetch")
):
    """
    Lab endpoint cho OAST/fetch external.

    Giai đoạn hiện tại:
    - Không fetch thật để tránh lỗi ngoài ý muốn.
    - Chỉ ghi nhận URL và log để AI Agent/Red Team dùng trong kịch bản.
    """

    request.state.detected_attack = "external_fetch_requested"
    request.state.mitre_technique = "T1048"
    request.state.security_message = f"External fetch requested: {url}"

    return {
        "message": "External fetch request received",
        "url": url,
        "mode": "simulated",
        "note": "Real outbound fetch can be enabled later in a controlled lab."
    }


# =========================
# 4. Admin / SOC Context
# =========================

@router.get("/api/v1/admin/system-status")
def system_status(request: Request):
    request.state.detected_attack = "none"
    request.state.security_message = "System status requested by admin/SOC"

    load_avg = None
    try:
        load_avg = os.getloadavg()
    except Exception:
        load_avg = None

    return {
        "status": "healthy",
        "service": "kma-backend",
        "container_ip": "172.20.0.3",
        "database": "kma-db:5432",
        "waf": "kma-waf:172.20.0.2",
        "siem": "kma-siem:172.20.0.4",
        "ai_agent": "kma-ai-agent:172.20.0.5",
        "cpu_load_avg": load_avg,
        "log_path": LOG_PATH
    }


@router.get("/api/v1/admin/security-logs")
def security_logs(request: Request, limit: int = 20):
    """
    Endpoint giả để AI Agent lấy log trực tiếp từ backend.
    """

    request.state.detected_attack = "admin_log_access"
    request.state.mitre_technique = "T1059"
    request.state.security_message = "Security logs requested through admin API"

    path = Path(LOG_PATH)

    if not path.exists():
        return {
            "message": "No log file found",
            "logs": []
        }

    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    last_lines = lines[-limit:]

    parsed_logs = []

    for line in last_lines:
        try:
            parsed_logs.append(json.loads(line))
        except Exception:
            parsed_logs.append({"raw": line})

    return {
        "message": "Security logs fetched",
        "count": len(parsed_logs),
        "logs": parsed_logs
    }


@router.post("/api/v1/admin/reboot-service")
def reboot_service(data: RebootServiceRequest, request: Request):
    """
    Endpoint mô phỏng cho AI-Assisted RCE scenario.

    Không thực thi shell thật.
    Chỉ mô phỏng hành động để an toàn trong giai đoạn hạ tầng.
    """

    if data.command:
        request.state.detected_attack = "ai_assisted_rce_attempt"
        request.state.mitre_technique = "LLM02"
        request.state.security_message = "Dangerous command field received in reboot-service request"
    else:
        request.state.detected_attack = "admin_service_reboot_requested"
        request.state.mitre_technique = None
        request.state.security_message = "Service reboot requested"

    return {
        "message": "Service reboot simulated",
        "service_name": data.service_name,
        "reason": data.reason,
        "command_received": bool(data.command),
        "status": "simulated_only"
    }
