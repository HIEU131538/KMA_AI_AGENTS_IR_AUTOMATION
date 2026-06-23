import json
import os
from pathlib import Path

from fastapi import APIRouter, Depends, Request

from app.logging_middleware import LOG_PATH
from app.schemas import RebootServiceRequest
from app.security import require_roles

from app.security_logger import write_auth_event
from app.security_event_service import write_security_event

from app.ai_analyzer import analyze_security
from app.memory.incident_store import (
    load_incidents,
    save_incidents
)

from app.siem_reader import (
    load_siem_alerts,
    alerts_to_threats
)

from app.memory.incident_engine import build_incident

from app.bridge_client import (
    send_batch_logs
)

from app.bridge_service import (
    load_normalized_logs
)

from app.bridge_adapter import (
    convert_ai_result
)

router = APIRouter(tags=["Admin"])


def set_auth_context(request: Request, current_user: dict):
    request.state.user_id = current_user["id"]
    request.state.username = current_user["username"]
    request.state.role = current_user["role"]
    request.state.jti = current_user.get("jti")

@router.get("/api/v1/admin/status")
def admin_status(
    request: Request,
    current_user: dict = Depends(require_roles(["admin", "manager"]))
):
    set_auth_context(request, current_user)

    request.state.security_message = "Admin status endpoint requested"

    return {
        "status": "healthy",
        "service": "kma-backend",
        "db": "connected",
        "waf": "behind-kma-waf",
        "siem": "log-volume-enabled"
    }


@router.get("/api/v1/admin/system-status")
def system_status(
    request: Request,
    current_user: dict = Depends(require_roles(["admin", "manager"]))
):
    set_auth_context(request, current_user)

    request.state.security_message = "System status requested by admin/SOC"

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
def security_logs(
    request: Request,
    limit: int = 20,
    current_user: dict = Depends(require_roles(["admin"]))
):
    set_auth_context(request, current_user)

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

    write_auth_event(
        event="security_logs_access",
        actor=current_user["username"],
        result="success",
        ip=request.client.host
    )

    write_security_event(
        event="security_logs_access",
        severity="medium",
        user=current_user["username"],
        ip=request.client.host
    )

    return {
        "message": "Security logs fetched",
        "count": len(parsed_logs),
        "logs": parsed_logs
    }


@router.post("/api/v1/admin/reboot-service")
def reboot_service(
    data: RebootServiceRequest,
    request: Request,
    current_user: dict = Depends(require_roles(["admin"]))
):
    set_auth_context(request, current_user)

    if data.command:
        request.state.detected_attack = "ai_assisted_rce_attempt"
        request.state.mitre_technique = "LLM02"
        request.state.security_message = "Dangerous command field received in reboot-service request"
    else:
        request.state.detected_attack = "admin_service_reboot_requested"
        request.state.security_message = "Service reboot requested"

    write_auth_event(
        event="service_reboot_request",
        actor=current_user["username"],
        target=data.service_name,
        result="success",
        ip=request.client.host
    )

    write_security_event(
        event="service_reboot_request",
        severity="high",
        user=current_user["username"],
        ip=request.client.host,
        details=data.service_name
    )

    return {
        "message": "Service reboot simulated",
        "service_name": data.service_name,
        "reason": data.reason,
        "command_received": bool(data.command),
        "status": "simulated_only"
    }

@router.get("/api/v1/security/events")
def get_security_events(
    request: Request,
    current_user: dict = Depends(require_roles(["admin"]))
):
    set_auth_context(request, current_user)

    path = "/var/log/kma-security/events.log"

    events = []

    try:
        with open(path, "r") as f:
            lines = f.readlines()

        for line in lines:
            events.append(json.loads(line))

        events.sort(
            key=lambda x: x["timestamp"],
            reverse=True
        )

        events = events[:100]

    except Exception:
        pass

    return {
        "count": len(events),
        "events": events
    }

@router.get("/api/v1/security/threats")
def get_threat_events(
    request: Request,
    current_user: dict = Depends(require_roles(["admin"]))
):
    set_auth_context(request, current_user)

    path = "/var/log/kma-threat/threat.log"

    events = []

    try:
        with open(path, "r") as f:
            lines = f.readlines()

        for line in lines:
            events.append(json.loads(line))

        events.sort(
            key=lambda x: x["timestamp"],
            reverse=True
        )

        events = events[:100]

    except Exception:
        pass

    return {
        "count": len(events),
        "threats": events
    }

@router.get("/api/v1/security/analyze")
def analyze_security_events(
    request: Request,
    current_user: dict = Depends(
        require_roles(["admin"])
    )
):
    set_auth_context(
        request,
        current_user
    )

    security_path = "/var/log/kma-security/events.log"
    threat_path = "/var/log/kma-threat/threat.log"

    events = []
    threats = []

    try:

        with open(
            security_path,
            "r"
        ) as f:

            for line in f.readlines():

                events.append(
                    json.loads(line)
                )

    except Exception:
        pass

    try:

        with open(
            threat_path,
            "r"
        ) as f:

            for line in f.readlines():

                threats.append(
                    json.loads(line)
                )

    except Exception:
        pass

    siem_alerts = load_siem_alerts()

    siem_threats = alerts_to_threats(
        siem_alerts
    )

    threats.extend(
        siem_threats
    )

    try:

        logs = load_normalized_logs()

        logs = [

            log

            for log in logs

            if log["event_type"] != "web_access"

        ]

        logs = logs[:10]

        print(
            f"[Dashboard] Sending {len(logs)} logs"
        )

        ai_result = send_batch_logs(
            logs,
            reset_memory=True
        )

        if "error" in ai_result:
            print(f"[Dashboard] AI Error: {ai_result['error']}")

        print("=" * 80)

        print(
            "[Dashboard] AI response received"
        )

        result = convert_ai_result(
            ai_result
        )

        print(result)

        required = [
            "attack_chain",
            "severity"
        ]

        for key in required:

            if key not in result:

               raise Exception(
                   f"Missing field: {key}"
               )

    except Exception as e:

        print(
            f"[Dashboard] AI failed: {e}"
        )

        print(
            "[Dashboard] Fallback to local analyzer"
        )

        result = analyze_security(
            events,
            threats
        )

    incident = build_incident(
        result["attack_chain"],
        result["severity"]
    )

    if incident:

        incident["profile"] = (
            result["profile"]
        )

        incident["timeline"] = (
            result["timeline"]
        )

        incidents = load_incidents()

        if incidents:

            incidents[-1] = incident

            save_incidents(
                incidents
            )

    result["incident"] = incident

    result["siem_alerts"] = (
        siem_alerts
    )

    return result

@router.get("/api/v1/security/incidents")
def get_incidents(
    request: Request,
    current_user: dict = Depends(
        require_roles(["admin"])
    )
):
    set_auth_context(request, current_user)

    incidents = load_incidents()

    incidents.sort(
        key=lambda x: x["created_at"],
        reverse=True
    )

    return {
        "count": len(incidents),
        "incidents": incidents
    }

@router.post(
    "/api/v1/bridge/send"
)
def bridge_send(
    current_user: dict = Depends(
        require_roles(["admin"])
    )
):

    logs = load_normalized_logs()

    if len(logs) == 0:

        print(
            "[Dashboard] No new logs"
        )

        return {
            "message": "No new logs to send",
            "sent": 0
        }

    MAX_BATCH_SIZE = 10

    logs = logs[:MAX_BATCH_SIZE]

    print(f"Bridge will send {len(logs)} logs")

    result = send_batch_logs(

        logs,

        reset_memory=True

    )

    return result
