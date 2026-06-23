import ipaddress
import os
import socket
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile

from app.schemas import ExportPDFRequest, DNSQueryLog
from app.security import get_current_user
from app.threat_logger import write_threat_event
from app.security_event_service import write_security_event

router = APIRouter(tags=["Tools"])


def set_auth_context(request: Request, current_user: dict):
    request.state.user_id = current_user["id"]
    request.state.username = current_user["username"]
    request.state.role = current_user["role"]
    request.state.jti = current_user.get("jti")


def get_allowed_networks():
    raw_networks = os.getenv(
        "SSRF_ALLOWED_NETWORKS",
        "172.20.0.0/24,127.0.0.0/8"
    )

    networks = []

    for item in raw_networks.split(","):
        item = item.strip()

        if item:
            networks.append(ipaddress.ip_network(item, strict=False))

    return networks


def get_fetch_timeout() -> float:
    try:
        return float(os.getenv("SSRF_FETCH_TIMEOUT", "3"))
    except ValueError:
        return 3.0


def get_response_mode() -> str:
    return os.getenv("SSRF_RESPONSE_MODE", "blind").lower()


def resolve_host_to_ips(hostname: str) -> list[str]:
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise HTTPException(
            status_code=400,
            detail=f"Could not resolve hostname: {hostname}"
        )

    ips = sorted({item[4][0] for item in addr_info})

    return ips


def is_ip_allowed(ip_value: str) -> bool:
    ip_obj = ipaddress.ip_address(ip_value)
    allowed_networks = get_allowed_networks()

    return any(ip_obj in network for network in allowed_networks)


def is_metadata_service(ip_value: str) -> bool:
    """
    Metadata service phổ biến trong cloud thường nằm ở 169.254.169.254.
    Trong lab này không fetch thật IP metadata để tránh hành vi nguy hiểm ngoài ý muốn.
    """
    return ip_value == "169.254.169.254"


def analyze_source_url(source_url: str) -> dict:
    parsed = urlparse(source_url)

    if parsed.scheme not in ["http", "https"]:
        raise HTTPException(
            status_code=400,
            detail="Only http and https schemes are allowed in this lab"
        )

    if not parsed.hostname:
        raise HTTPException(
            status_code=400,
            detail="Invalid source_url: hostname is missing"
        )

    hostname = parsed.hostname
    resolved_ips = resolve_host_to_ips(hostname)

    metadata_ips = [ip for ip in resolved_ips if is_metadata_service(ip)]
    allowed_ips = [ip for ip in resolved_ips if is_ip_allowed(ip)]

    return {
        "source_url": source_url,
        "scheme": parsed.scheme,
        "hostname": hostname,
        "port": parsed.port,
        "path": parsed.path,
        "resolved_ips": resolved_ips,
        "metadata_ips": metadata_ips,
        "allowed_ips": allowed_ips,
        "is_allowed_internal_lab_target": len(allowed_ips) > 0,
        "is_metadata_target": len(metadata_ips) > 0
    }


async def fetch_url_metadata(source_url: str) -> dict:
    timeout = get_fetch_timeout()

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False
    ) as client:
        response = await client.get(source_url)

    content_type = response.headers.get("content-type")
    content_length = response.headers.get("content-length")

    result = {
        "status_code": response.status_code,
        "content_type": content_type,
        "content_length": content_length,
        "final_url": str(response.url)
    }

    if get_response_mode() == "demo":
        text_preview = response.text[:300] if response.text else ""
        result["preview"] = text_preview
    else:
        result["preview"] = None

    return result


@router.post("/api/v1/tools/export-pdf")
async def export_pdf(
    data: ExportPDFRequest,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """
    Controlled SSRF Lab Endpoint.

    Ý tưởng nghiệp vụ:
    - Backend nhận source_url.
    - Backend fetch nội dung URL.
    - Backend giả lập tạo PDF.

    Lab control:
    - Chỉ fetch các target thuộc mạng Docker lab đã cấu hình.
    - Không fetch Internet tự do.
    - Không fetch metadata service thật.
    - Có blind mode để không trả nội dung fetch về attacker.
    """

    set_auth_context(request, current_user)

    analysis = analyze_source_url(data.source_url)

    if analysis["is_metadata_target"]:
        request.state.detected_attack = "ssrf_metadata_request_blocked_by_lab_scope"

        write_threat_event(
            attack="ssrf_metadata_request",
            severity="high",
            user=current_user["username"],
            ip=request.client.host,
            mitre="T1190"
        )

        request.state.mitre_technique = "T1190"
        request.state.security_message = (
            f"source_url points to cloud metadata service. "
            f"hostname={analysis['hostname']}, resolved_ips={analysis['resolved_ips']}. "
            f"Fetch blocked by controlled lab scope."
        )

        return {
            "message": "PDF export rejected by controlled SSRF lab policy",
            "source_url": data.source_url,
            "analysis": analysis,
            "fetch_executed": False,
            "reason": "metadata service target is not fetched in this controlled lab"
        }

    if not analysis["is_allowed_internal_lab_target"]:
        request.state.detected_attack = "external_url_blocked_by_lab_scope"
        request.state.mitre_technique = "T1190"
        request.state.security_message = (
            f"source_url is outside allowed Docker lab networks. "
            f"hostname={analysis['hostname']}, resolved_ips={analysis['resolved_ips']}."
        )

        raise HTTPException(
            status_code=400,
            detail={
                "message": "External URL is outside controlled lab scope",
                "analysis": analysis
            }
        )

    request.state.detected_attack = "ssrf_internal_request"

    write_security_event(
        event="employee_export_pdf",
        severity="medium",
        user=current_user["username"],
        ip=request.client.host,
        details=data.source_url
    )

    write_threat_event(
        attack="ssrf_internal_request",
        severity="high",
        user=current_user["username"],
        ip=request.client.host,
        mitre="T1190"
    )

    request.state.mitre_technique = "T1190"
    request.state.security_message = (
        f"source_url points to internal/private Docker lab address. "
        f"hostname={analysis['hostname']}, resolved_ips={analysis['resolved_ips']}, "
        f"allowed_ips={analysis['allowed_ips']}"
    )

    try:
        fetch_result = await fetch_url_metadata(data.source_url)
    except Exception as exc:
        request.state.security_message = (
            f"SSRF internal request attempted but fetch failed. "
            f"source_url={data.source_url}, error={str(exc)}"
        )

        return {
            "message": "PDF export job created, but internal fetch failed",
            "source_url": data.source_url,
            "analysis": analysis,
            "fetch_executed": True,
            "fetch_error": str(exc),
            "mode": get_response_mode()
        }

    return {
        "message": "PDF export simulated",
        "source_url": data.source_url,
        "analysis": analysis,
        "fetch_executed": True,
        "fetch_result": fetch_result,
        "mode": get_response_mode(),
        "lab_note": (
            "Controlled SSRF lab endpoint. In blind mode, response body is not returned."
        )
    }


@router.post("/api/v1/tools/upload-cv")
async def upload_cv(
    request: Request,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    set_auth_context(request, current_user)

    request.state.detected_attack = "rag_poisoning_surface_access"
    request.state.mitre_technique = "T1562"
    request.state.security_message = f"CV uploaded: {file.filename}"

    return {
        "message": "CV uploaded",
        "filename": file.filename,
        "content_type": file.content_type
    }


@router.post("/api/v1/tools/dns-query")
async def dns_query_log(
    data: DNSQueryLog,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """
    Endpoint mô phỏng DNS resolver nội bộ nhận query từ các host trong mạng.
    Trong thực tế, đây là nơi DNS sniffer (Zeek/Suricata) forward log vào hệ thống.
    Attacker dùng DNS tunneling sẽ để lộ query có subdomain entropy cao tại đây.
    """
    set_auth_context(request, current_user)

    request.state.detected_attack = "dns_tunnel"
    request.state.mitre_technique = "T1048.001"
    request.state.security_message = (
        f"DNS tunneling detected: high-entropy subdomain query [{data.query}] "
        f"from {data.client_ip} via {data.server_id}"
    )

    write_threat_event(
        attack=f"DNS Tunneling — query: {data.query[:60]}",
        severity="high",
        user=current_user.get("username", "unknown"),
        ip=data.client_ip,
        mitre="T1048.001"
    )

    return {
        "message": "DNS query logged by internal resolver",
        "query": data.query,
        "verdict": "suspicious — high entropy subdomain detected",
        "mitre": "T1048.001"
    }


@router.get("/api/v1/tools/fetch-external")
def fetch_external(
    request: Request,
    url: str = Query(..., description="External URL to fetch"),
    current_user: dict = Depends(get_current_user)
):
    set_auth_context(request, current_user)

    request.state.detected_attack = "external_fetch_requested"
    request.state.mitre_technique = "T1048"
    request.state.security_message = f"External fetch requested: {url}"

    return {
        "message": "External fetch request received",
        "url": url,
        "mode": "simulated",
        "note": "Real outbound fetch is not enabled in this controlled lab."
    }
