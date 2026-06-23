import base64
import json
import os
import time
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import Request

LOG_PATH = "/var/log/kma-app/app.log"

MAX_BODY_LOG_SIZE = 4096

SENSITIVE_KEYS = {
    "password",
    "hashed_password",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "jwt",
    "jwt_secret",
    "jwt_secret_key",
    "secret",
    "private_key",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def mask_sensitive_value(value: Any) -> str:
    return "***MASKED***"


def sanitize_json(data: Any):
    """
    Mask các trường nhạy cảm trước khi ghi log.
    Tránh log password, access_token, secret key.
    """
    if isinstance(data, dict):
        sanitized = {}

        for key, value in data.items():
            if key.lower() in SENSITIVE_KEYS:
                sanitized[key] = mask_sensitive_value(value)
            else:
                sanitized[key] = sanitize_json(value)

        return sanitized

    if isinstance(data, list):
        return [sanitize_json(item) for item in data]

    return data


def normalize_body(raw_body: bytes, content_type: str | None):
    """
    Chuẩn hóa request body để AI Agent đọc được.
    - JSON: parse và mask field nhạy cảm.
    - Multipart/file upload: không log raw binary.
    - Text thường: log text giới hạn kích thước.
    - Binary: base64 encode.
    """
    if not raw_body:
        return None

    content_type = content_type or ""
    truncated = len(raw_body) > MAX_BODY_LOG_SIZE
    body = raw_body[:MAX_BODY_LOG_SIZE]

    if "multipart/form-data" in content_type:
        return {
            "encoding": "metadata",
            "content": "multipart/form-data omitted from log",
            "truncated": truncated
        }

    if "application/json" in content_type:
        try:
            parsed = json.loads(body.decode("utf-8"))
            return {
                "encoding": "json",
                "content": sanitize_json(parsed),
                "truncated": truncated
            }
        except Exception:
            pass

    try:
        decoded = body.decode("utf-8")
        return {
            "encoding": "utf-8",
            "content": decoded,
            "truncated": truncated
        }
    except UnicodeDecodeError:
        return {
            "encoding": "base64",
            "content": base64.b64encode(body).decode("ascii"),
            "truncated": truncated
        }


def get_client_ip(request: Request) -> str | None:
    x_forwarded_for = request.headers.get("x-forwarded-for")
    x_real_ip = request.headers.get("x-real-ip")

    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()

    if x_real_ip:
        return x_real_ip.strip()

    if request.client:
        return request.client.host

    return None


def extract_safe_headers(request: Request) -> dict:
    """
    Chỉ log các header an toàn.
    Không log Authorization vì chứa Bearer token.
    """
    return {
        "host": request.headers.get("host"),
        "user-agent": request.headers.get("user-agent"),
        "x-forwarded-for": request.headers.get("x-forwarded-for"),
        "x-real-ip": request.headers.get("x-real-ip"),
        "content-type": request.headers.get("content-type"),
    }


def write_json_log(record: dict):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def register_logging_middleware(app):
    @app.middleware("http")
    async def security_logging_middleware(request: Request, call_next):
        start_time = time.time()
        event_id = str(uuid4())

        raw_body = await request.body()
        content_type = request.headers.get("content-type")
        normalized_body = normalize_body(raw_body, content_type)

        # Cho phép route phía sau vẫn đọc được body sau khi middleware đã đọc.
        async def receive():
            return {
                "type": "http.request",
                "body": raw_body,
                "more_body": False
            }

        request._receive = receive

        response = None
        status_code = 500

        try:
            response = await call_next(request)
            status_code = response.status_code
            return response

        except Exception as exc:
            request.state.detected_attack = getattr(
                request.state,
                "detected_attack",
                "backend_exception"
            )
            request.state.security_message = f"Unhandled backend exception: {str(exc)}"
            status_code = 500
            raise

        finally:
            latency_ms = round((time.time() - start_time) * 1000, 2)

            _detected = getattr(request.state, "detected_attack", "none")
            _mitre    = getattr(request.state, "mitre_technique", None)
            _message  = getattr(request.state, "security_message", None)

            if _detected == "none":
                _has_te = "transfer-encoding" in request.headers
                _has_cl = "content-length" in request.headers
                _has_internal_trace = "x-internal-trace" in request.headers
                _has_fwd_host = request.headers.get("x-forwarded-host", "")

                if _has_te and _has_cl:
                    _detected = "http_smuggling"
                    _mitre    = "T1190"
                    _message  = (
                        f"HTTP Request Smuggling detected: "
                        f"conflicting Content-Length and Transfer-Encoding headers "
                        f"on {request.method} {request.url.path}"
                    )
                elif _has_te and "chunked" in request.headers.get("transfer-encoding", "").lower():
                    _detected = "http_smuggling"
                    _mitre    = "T1190"
                    _message  = (
                        f"HTTP Request Smuggling probe detected: "
                        f"Transfer-Encoding: chunked without Content-Length "
                        f"on {request.method} {request.url.path}"
                    )
                elif _has_internal_trace or ("internal" in _has_fwd_host.lower()):
                    _detected = "header_injection"
                    _mitre    = "T1190"
                    _message  = (
                        f"Header Injection detected: "
                        f"X-Internal-Trace or X-Forwarded-Host pointing to internal host "
                        f"from external client on {request.url.path}"
                    )

            log_record = {
                "timestamp": utc_now_iso(),
                "source": "backend",
                "event_id": event_id,
                "service": "kma-backend",
                "client_ip": get_client_ip(request),
                "request": {
                    "method": request.method,
                    "url": request.url.path,
                    "query_params": dict(request.query_params),
                    "headers": extract_safe_headers(request),
                    "body": normalized_body
                },
                "response": {
                    "status_code": status_code,
                    "latency_ms": latency_ms
                },
                "auth_context": {
                    "user_id": getattr(request.state, "user_id", None),
                    "username": getattr(request.state, "username", None),
                    "role": getattr(request.state, "role", None),
                    "jti": getattr(request.state, "jti", None)
                },
                "security_metadata": {
                    "waf_decision": getattr(request.state, "waf_decision", "allowed"),
                    "detected_attack": _detected,
                    "mitre_technique": _mitre,
                    "message": _message
                }
            }

            write_json_log(log_record)
