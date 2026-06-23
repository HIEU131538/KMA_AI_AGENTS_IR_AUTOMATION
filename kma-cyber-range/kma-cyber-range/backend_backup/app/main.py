import json
import os
import time
from datetime import datetime, timedelta

from dotenv import load_dotenv
from fastapi import FastAPI, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
from pydantic import BaseModel

load_dotenv("/app/backend/.env")

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev_secret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

LOG_PATH = "/var/log/kma-app/app.log"

app = FastAPI(
    title="KMA HR Management API",
    description="Backend API for KMA Cyber Range",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class LoginRequest(BaseModel):
    username: str
    password: str


class ExportPDFRequest(BaseModel):
    source_url: str


@app.middleware("http")
async def security_logging_middleware(request: Request, call_next):
    start_time = time.time()
    raw_body = await request.body()

    try:
        body_text = raw_body.decode("utf-8") if raw_body else None
    except UnicodeDecodeError:
        body_text = "<binary_payload>"

    response = await call_next(request)

    latency_ms = round((time.time() - start_time) * 1000, 2)

    x_forwarded_for = request.headers.get("x-forwarded-for")
    client_ip = (
        x_forwarded_for.split(",")[0].strip()
        if x_forwarded_for
        else request.client.host if request.client else None
    )

    log_record = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "service": "kma-backend",
        "client_ip": client_ip,
        "request": {
            "method": request.method,
            "url": request.url.path,
            "headers": {
                "user-agent": request.headers.get("user-agent"),
                "x-forwarded-for": request.headers.get("x-forwarded-for")
            },
            "body": body_text
        },
        "response": {
            "status_code": response.status_code,
            "latency_ms": latency_ms
        },
        "security_metadata": {
            "waf_decision": getattr(request.state, "waf_decision", "allowed"),
            "detected_attack": getattr(request.state, "detected_attack", "none"),
            "mitre_technique": getattr(request.state, "mitre_technique", None),
            "message": getattr(request.state, "security_message", None)
        }
    }

    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_record, ensure_ascii=False) + "\n")

    return response


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "kma-app",
        "ip": "172.20.0.3"
    }


@app.post("/auth/login")
def login(data: LoginRequest):
    role = "admin" if data.username == "admin" else "employee"

    payload = {
        "sub": data.username,
        "role": role,
        "jti": f"token-{data.username}-{int(time.time())}",
        "exp": datetime.utcnow() + timedelta(hours=2)
    }

    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "username": data.username,
            "role": role
        }
    }


@app.get("/api/v1/employees")
def list_employees():
    return {
        "employees": [
            {
                "id": 1,
                "full_name": "Nguyen Van A",
                "department": "Board",
                "salary": 50000000,
                "phone": "0900000001",
                "owner_user_id": "admin"
            },
            {
                "id": 2,
                "full_name": "Tran Thi B",
                "department": "HR",
                "salary": 20000000,
                "phone": "0900000002",
                "owner_user_id": "employee01"
            }
        ]
    }


@app.get("/api/v1/employees/{employee_id}")
def get_employee(employee_id: int):
    fake_employees = {
        1: {
            "id": 1,
            "full_name": "Nguyen Van A",
            "department": "Board",
            "salary": 50000000,
            "phone": "0900000001",
            "owner_user_id": "admin"
        },
        2: {
            "id": 2,
            "full_name": "Tran Thi B",
            "department": "HR",
            "salary": 20000000,
            "phone": "0900000002",
            "owner_user_id": "employee01"
        }
    }

    return fake_employees.get(employee_id, {"message": "Employee not found"})


@app.post("/api/v1/tools/export-pdf")
def export_pdf(data: ExportPDFRequest):
    return {
        "message": "PDF export job created",
        "source_url": data.source_url
    }


@app.post("/api/v1/tools/upload-cv")
async def upload_cv(file: UploadFile = File(...)):
    return {
        "message": "CV uploaded",
        "filename": file.filename,
        "content_type": file.content_type
    }


@app.get("/api/v1/admin/status")
def admin_status():
    return {
        "status": "healthy",
        "service": "kma-backend",
        "db": "connected",
        "waf": "behind-kma-waf",
        "siem": "log-volume-enabled"
    }

# Extra routes agreed with AI Agent and Red Team
from app.routes_extra import router as extra_router
app.include_router(extra_router)
