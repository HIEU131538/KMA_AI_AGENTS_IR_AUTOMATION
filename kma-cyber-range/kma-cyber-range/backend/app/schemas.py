from typing import Optional

from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


class Fido2RegisterRequest(BaseModel):
    username: str


class Fido2LoginRequest(BaseModel):
    username: str


class EmployeeCreate(BaseModel):
    user_id: Optional[int] = None
    full_name: str
    department: str
    position: Optional[str] = None
    salary: Optional[int] = None
    phone: Optional[str] = None
    email: Optional[str] = None


class EmployeeUpdate(BaseModel):
    user_id: Optional[int] = None
    full_name: Optional[str] = None
    department: Optional[str] = None
    position: Optional[str] = None
    salary: Optional[int] = None
    phone: Optional[str] = None
    email: Optional[str] = None


class ProfileUpdateRequest(BaseModel):
    full_name: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    department: Optional[str] = None
    role: Optional[str] = None


class ExportPDFRequest(BaseModel):
    source_url: str


class RebootServiceRequest(BaseModel):
    service_name: str
    reason: Optional[str] = None
    command: Optional[str] = None

class DNSQueryLog(BaseModel):
    query: str
    query_type: Optional[str] = "A"
    client_ip: Optional[str] = "unknown"
    server_id: Optional[str] = "dns-internal-core"

class WebAuthnLoginStartRequest(BaseModel):
    username: str


class WebAuthnFinishRequest(BaseModel):
    credential: dict
