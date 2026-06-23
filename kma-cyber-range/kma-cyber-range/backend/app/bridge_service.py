import json
from pathlib import Path

OFFSET_FILE = (
    "/app/backend/app/offsets.json"
)

MAX_LOGS_PER_FILE = 20

LOG_FILES = [

    "/var/log/kma-app/app.log",

    "/var/log/kma-auth/auth.log",

]

EVENT_TYPE_MAP = {

    # Request bình thường
    "none": "web_access",

    # Scan
    "port_scan": "scan",
    "directory_scan": "scan",

    # Auth
    "login_failed": "login",
    "login_success": "login",
    "logout": "auth",
    "jwt_validate": "auth",

    #BOLA
    "bola_attempt": "bola_attempt",

    # Brute Force
    "bruteforce": "brute",
    "brute_force": "brute",

    # SQLi
    "sql_injection": "sql",
    "sqli_attempt": "sql",

    # SSRF
    "ssrf_attempt": "web_attack",
    "ssrf_internal_request": "web_attack",
    "ssrf_metadata_request": "web_attack",

    # Privilege Escalation / Mass Assignment
    "mass_assignment_role_escalation": "privilege_escalation",
    "privilege_escalation": "privilege_escalation",

    # RCE
    "rce_attempt": "rce_attempt",
    "ai_assisted_rce_attempt": "rce_attempt",

    # Command Injection
    "command_execution": "cmd",
    "cmd_injection": "cmd",

    # Shell
    "reverse_shell": "shell",
    "web_shell": "shell",

    # Data Leak
    "data_dump": "dump",
    "data_exfiltration": "exfil",

    # DNS Tunneling
    "dns_tunnel": "dns_query",
    "dns_tunneling": "dns_query",

    # RAG Poisoning surface
    "rag_poisoning_surface_access": "web_attack",

    # HTTP Smuggling / Header Injection
    "http_smuggling": "web_attack",
    "header_injection": "web_attack",

    # SSRF variants (tên đầy đủ từ route handler)
    "ssrf_metadata_request_blocked_by_lab_scope": "web_attack",
    "external_url_blocked_by_lab_scope": "web_attack",

    # Backend Error
    "backend_exception": "web_attack",

    # Admin
    "admin_log_access": "web_access",
    "admin_service_reboot_requested": "web_access",
}

URL_EVENT_MAP = {

    "/auth/login": "login",

    "/auth/logout": "auth",

    "/auth/session/validate": "auth",

    "/auth/fido2/login": "login",

    "/auth/fido2/register": "auth",


    "/api/v1/tools/export-pdf": "web_attack",

    "/api/v1/tools/upload-cv": "web_attack",

    "/api/v1/employees": "web_access",
    "/api/v1/departments": "web_access",

    "/api/v1/admin": "web_access",
}

def load_offsets():

    try:

        with open(
            OFFSET_FILE,
            "r"
        ) as f:

            return json.load(f)

    except Exception:

        return {}

def save_offsets(offsets):

    print("Saving offsets...")
    print(offsets)
    print("File =", OFFSET_FILE)

    with open(
        OFFSET_FILE,
        "w"
    ) as f:

        json.dump(
            offsets,
            f,
            indent=4
        )

    print("Saved.")

def load_raw_logs():

    logs = []

    offsets = load_offsets()

    for path in LOG_FILES:

        print("=" * 80)
        print(path)

        file = Path(path)

        if not file.exists():
            continue

        try:

            with open(
                file,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as f:

                last_offset = offsets.get(
                    path,
                    0
                )

                print("offset =", last_offset)

                f.seek(last_offset)

                count = 0
                total_reads = 0
                MAX_TOTAL_READS = 500  # tránh loop vô hạn khi file rất lớn

                while count < MAX_LOGS_PER_FILE and total_reads < MAX_TOTAL_READS:

                    pos = f.tell()

                    line = f.readline()

                    if not line:
                        break

                    total_reads += 1

                    try:

                       data = json.loads(line)

                    except Exception:

                       continue

                    request = data.get("request", {})

                    url = request.get("url", "")

                    IGNORE_PREFIXES = [

                       "/api/v1/bridge",

                       "/api/v1/security",

                    ]

                    if any(
                       url.startswith(prefix)
                       for prefix in IGNORE_PREFIXES
                    ):
                       continue

                    # Bỏ qua log không có sự kiện bảo mật (health check, request thường)
                    # để chúng không lấp đầy giới hạn 20 log/cycle
                    _d_attack = (
                        data.get("security_metadata", {})
                            .get("detected_attack", "none")
                    )
                    if _d_attack == "none":
                        continue

                    logs.append(
                        (
                            path,
                            line.strip()
                        )
                    )

                    count += 1

                    if count >= MAX_LOGS_PER_FILE:
                        break

                offsets[path] = f.tell()

                print("path =", path)
                print("tell =", f.tell())
                print("offsets =", offsets)

                print("Offsets before save:")
                print(offsets)

                save_offsets(offsets)

        except Exception:
            import traceback

            print("=" * 80)
            traceback.print_exc()
            print("=" * 80)

            raise

    save_offsets(
        offsets
    )

    return logs

def normalize_log(
    source,
    line
):

    try:

        data = json.loads(line)

    except Exception:

        data = {
            "message": line
        }

    request = data.get("request") or {}

    if not isinstance(request, dict):
        request = {}

    body = request.get("body") or {}

    if not isinstance(body, dict):
        body = {}

    content = body.get("content") or {}

    if not isinstance(content, dict):
        content = {}

    security = data.get("security_metadata") or {}

    if not isinstance(security, dict):
        security = {}

    detected_attack = security.get("detected_attack")

    url = request.get("url", "")

    INTERNAL_ENDPOINTS = [

        "/api/v1/security/",

        "/api/v1/bridge/",

    ]

    for internal in INTERNAL_ENDPOINTS:

        if url.startswith(internal):

            return None

    if detected_attack and detected_attack != "none":

        event_type = EVENT_TYPE_MAP.get(
            detected_attack,
            "web_access"
        )

    else:

        event_type = "web_access"

        for path, mapped_event in URL_EVENT_MAP.items():

            if path in url:

                event_type = mapped_event

                break

    # Giữ lại payload body để AI Agent extractor scan được attack keyword
    # (SQLi, SSRF URL, JWT payload, v.v.)
    raw_content = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)

    return {

        "timestamp":

            data.get(
                "timestamp"
            ),

        "source_ip":

            (
                data.get("client_ip")
                or
                data.get("source_ip")
                or
                data.get("ip")
                or
                "unknown"
            ),

        "event_type": event_type,

        "message":

            (
                security.get("message")
                or
                data.get("message")
                or
                request.get("url")
                or
                "unknown"
            ),

        "method":

            request.get("method"),

        "url":

            request.get("url"),

        "user":

            (
                data.get("auth_context", {})
                .get("username")
            ),

        "mitre":
            security.get("mitre_technique"),

        "severity":
            (
                security.get("severity")
                or
                data.get("severity")
            ),

        "status":
            (
                data.get("response", {})
                .get("status_code")
            ),

        "payload":
            raw_content if raw_content and raw_content != "{}" else None,

        "query_params":
            request.get("query_params"),

        "detected_attack":
            detected_attack or "none",

    }

def load_normalized_logs():

    normalized = []

    raw_logs = load_raw_logs()

    print(
        f"[Bridge] Raw logs: {len(raw_logs)}"
    )

    for source, line in raw_logs:

        item = normalize_log(
            source,
            line
        )

        if item is None:
            continue

        normalized.append(item)

    print(
        f"[Bridge] Normalized logs: {len(normalized)}"
    )

    print("=" * 80)
    print("NORMALIZED LOGS")

    for log in normalized:
        print(json.dumps(log, indent=2))

    print("=" * 80)

    return normalized
