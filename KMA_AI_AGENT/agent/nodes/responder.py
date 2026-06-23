import json
import os
import subprocess
import logging
import requests
import ipaddress  
from agent.state import SOCAgentState

# Lấy cấu hình từ biến môi trường
ALLOW_LIVE_MODE = os.getenv("ALLOW_LIVE_MODE", "true").lower() == "true"

from dotenv import load_dotenv
load_dotenv()

def get_soar_mode() -> str:
    """Đọc file config 1 lần duy nhất để lấy công tắc LIVE/SIMULATION"""
    try:
        with open("config.json", "r") as f:
            config = json.load(f)
            requested_mode = config.get("SOAR_MODE", "SIMULATION").upper()
            
            if requested_mode == "LIVE" and not ALLOW_LIVE_MODE:
                print("⚠️ [WARNING] Giao diện yêu cầu LIVE, nhưng ALLOW_LIVE_MODE đang tắt! Ép về SIMULATION.")
                return "SIMULATION"
                
            return requested_mode
    except FileNotFoundError:
        return "SIMULATION"

def is_valid_ip(ip: str) -> bool:
    """Hàm bảo mật: Xác thực định dạng IP để chống Command Injection"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# ==========================================
# CÁC HÀM THỰC CHIẾN SOAR (ACTION PLAYBOOKS)
# ==========================================

def execute_block_ip(ip_address: str, mode: str) -> str:
    if mode == "SIMULATION":
        return f"[SIMULATION] Đã giả lập chặn IP {ip_address}."
    try:
        check_cmd = ["iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"]
        add_cmd = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
        
        try:
            subprocess.run(check_cmd, capture_output=True, check=True)
            return f"[*] THỰC CHIẾN (LIVE): IP {ip_address} đã bị Block từ trước, bỏ qua."
        except subprocess.CalledProcessError:
            subprocess.run(add_cmd, capture_output=True, text=True, check=True)
            return f"[+] THỰC CHIẾN (LIVE): Đã đưa IP {ip_address} vào Blacklist của iptables."
    except Exception as e:
        return f"[-] LỖI BLOCK IP: {str(e)}"

def execute_network_block_full(ip_address: str, mode: str) -> str:
    """Cô lập hoàn toàn một IP ở cấp độ mạng — chặn cả INPUT, OUTPUT, FORWARD.
    Đây là mức cao nhất, tương đương network-level isolation không cần Docker."""
    if mode == "SIMULATION":
        return f"[SIMULATION] Đã giả lập Network Block Full (INPUT+OUTPUT+FORWARD) cho IP {ip_address}."
    results = []
    for chain, flag in [("INPUT", "-s"), ("OUTPUT", "-d"), ("FORWARD", "-s")]:
        try:
            check = ["iptables", "-C", chain, flag, ip_address, "-j", "DROP"]
            add   = ["iptables", "-A", chain, flag, ip_address, "-j", "DROP"]
            try:
                subprocess.run(check, capture_output=True, check=True)
                results.append(f"{chain}: rule đã tồn tại.")
            except subprocess.CalledProcessError:
                subprocess.run(add, capture_output=True, check=True)
                results.append(f"{chain}: DROP rule đã thêm.")
        except Exception as e:
            results.append(f"{chain}: LỖI — {e}")
    return f"[+] NETWORK_BLOCK_FULL (LIVE) IP {ip_address}: {' | '.join(results)}"

def execute_throttle_ip(ip_address: str, mode: str, rate_limit: str = "5/m") -> str:
    if mode == "SIMULATION":
        return f"[SIMULATION] Mô phỏng: Đã giả lập bóp băng thông IP {ip_address} xuống {rate_limit}."
    try:
        check_limit = ["iptables", "-C", "INPUT", "-s", ip_address, "-m", "limit", "--limit", rate_limit, "-j", "ACCEPT"]
        try:
            subprocess.run(check_limit, capture_output=True, check=True)
            return f"[*] THROTTLE (LIVE): IP {ip_address} đã bị bóp băng thông từ trước."
        except subprocess.CalledProcessError:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-m", "limit", "--limit", rate_limit, "-j", "ACCEPT"], check=True)
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            return f"[~] THROTTLE (LIVE): Đã bóp băng thông IP {ip_address} xuống mức {rate_limit}."
    except Exception as e:
        return f"[-] LỖI THROTTLE IP {ip_address}: {str(e)}"

def execute_monitor_ip(ip_address: str, mode: str) -> str:
    try:
        os.makedirs("watchlist", exist_ok=True)
        filepath = "watchlist/suspect_ips.txt"
        existing_ips = set()
        
        if os.path.exists(filepath):
            with open(filepath, "r") as f:
                existing_ips = set(line.strip() for line in f)
                
        if ip_address not in existing_ips:
            with open(filepath, "a") as f:
                f.write(f"{ip_address}\n")
            return f"[*] MONITOR: Đã thêm mới IP {ip_address} vào Watchlist."
        else:
            return f"[*] MONITOR: IP {ip_address} đã tồn tại trong Watchlist, bỏ qua."
    except Exception as e:
        return f"[-] LỖI MONITOR IP: {str(e)}"

def execute_alert_telegram(message: str, mode: str) -> str:
    if mode == "SIMULATION":
        return f"[SIMULATION] Mô phỏng Gửi Alert: {message}"
    
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
    
    if not bot_token or not chat_id:
        return f"[-] LỖI TELEGRAM: Thiếu TELEGRAM_BOT_TOKEN hoặc TELEGRAM_CHAT_ID trong file .env"
        
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        resp = requests.post(url, json={"chat_id": chat_id, "text": message}, timeout=5)
        if resp.status_code == 200:
            return f"[!] ALERT (LIVE): Đã bắn thông báo Telegram thành công!"
        else:
            return f"[-] LỖI TELEGRAM API: {resp.text}"
    except Exception as e:
        return f"[-] LỖI KẾT NỐI TELEGRAM: {str(e)}"

# ==========================================
# TRẠM RESPONDER (NÃO BỘ ĐIỀU PHỐI)
# ==========================================
def node_responder(state: SOCAgentState):
    current_mode = get_soar_mode()
    print(f"\n[Trạm 4 - Responder] Đang đánh giá rủi ro... (MODE HIỆN TẠI: {current_mode})")
    
    severity = state.get("severity", "low").lower()
    evidence = state.get("evidence_strength", 0.0) 
    knowledge_conflict = state.get("knowledge_conflict", False)
    is_suspicious = state.get("is_suspicious", False)
    
    # BẢO MẬT: Validate IP trước khi xử lý
    source_ip = state.get("extracted_ioc", {}).get("source_ip", "")
    if not source_ip or not is_valid_ip(source_ip):
        # Fallback xuống raw log
        raw_log = state.get("raw_log", {})
        if isinstance(raw_log, dict):
            temp_ip = raw_log.get("source_ip", "")
            source_ip = temp_ip if is_valid_ip(temp_ip) else "Unknown_IP"
        else:
            source_ip = "Unknown_IP"
            
    if source_ip == "Unknown_IP":
        print("⚠️ CẢNH BÁO: Không thể xác thực được Source IP (Có thể là tấn công chèn mã hoặc Log hỏng).")
    
    notes = []
    notes.append(f"Responder: Chế độ SOAR hiện tại là {current_mode}.")
    
    action = "ignore" 
    reason = "Không có mối đe dọa."
    
    # 1. MA TRẬN ỨNG PHÓ RỦI RO
    if severity == "critical":
        if evidence >= 0.90:
            action = "network_block_full"
            reason = f"Kill chain xác nhận (Evidence={evidence}). Cô lập hoàn toàn IP — chặn INPUT+OUTPUT+FORWARD."
        elif evidence >= 0.70:
            action = "block_ip"
            reason = f"Mức Critical, bằng chứng khá (Evidence={evidence}). Chặn IP chiều vào (INPUT)."
        else:
            action = "alert_operator"
            reason = "Mức Critical nhưng bằng chứng chưa đủ mạnh. Cần SOC Analyst xác nhận."
            
    elif severity == "high":
        if evidence >= 0.85:
            action = "throttle"
            reason = f"Mức High, bằng chứng mạnh (Evidence={evidence}). Bóp băng thông/Ngắt kết nối tạm thời."
        else:
            action = "alert_operator"
            reason = "Mức High nhưng bằng chứng yếu. Cần SOC Analyst xác nhận."
            
    elif severity == "medium":
        if evidence >= 0.70:
            action = "alert"
            reason = "Mức Medium, có bằng chứng. Bắn cảnh báo toàn hệ thống."
        elif evidence >= 0.40:
            action = "alert_operator"
            reason = "Mức Medium, bằng chứng trung bình. Cần chuyên gia xem xét chéo."
        else:
            action = "monitor"
            reason = "Mức Medium, bằng chứng yếu. Đưa vào danh sách giám sát (Monitor)."
            
    elif severity == "low":
        # CHỈNH SỬA: Loại bỏ evidence >= 0.9, chỉ dùng is_suspicious
        if is_suspicious:
            action = "monitor"
            reason = "Không có IOC trực tiếp nhưng hành vi bất thường theo Correlator (is_suspicious=True). Bật theo dõi."
        else:
            action = "ignore"
            reason = "Lưu lượng truy cập an toàn, hợp lệ."

    # 2. LỚP PHÒNG NGỰ KNOWLEDGE CONFLICT
    if knowledge_conflict:
        notes.append("Responder [SKEPTICISM]: CẢNH BÁO - AI phát hiện mâu thuẫn tri thức.")
        if action == "isolate_container" and evidence >= 0.90:
            notes.append(f"Responder [OVERRIDE]: Mâu thuẫn tri thức BỊ BỎ QUA do bằng chứng trực tiếp quá mạnh. Giữ lệnh PAUSE CONTAINER.")
        elif action in ["network_block_full", "block_ip"]:
            original_action = action
            action = "alert_operator"
            reason = f"Hạ cấp từ {original_action.upper()} xuống ALERT_OPERATOR vì hoài nghi tài liệu RAG."
            notes.append(f"Responder: Tước quyền tự động hóa để đảm bảo an toàn.")

    notes.append(f"Responder [Quyết định]: {action.upper()} - {reason}")
    print(f"[+] Quyết định hành động: {action.upper()} | Evidence: {evidence}")

    # 3. THỰC THI SOAR PLAYBOOK
    notes.append(f"Responder [SOAR Execution]: Tiến hành xử lý IP {source_ip}...")
    
    if source_ip and source_ip != "Unknown_IP":
        if action == "network_block_full":
            notes.append(execute_network_block_full(source_ip, current_mode))
            notes.append(execute_alert_telegram(f"🚨 [CRITICAL] NETWORK BLOCK FULL — IP {source_ip} bị cô lập hoàn toàn (INPUT+OUTPUT+FORWARD)", current_mode))
            
        elif action == "block_ip":
            notes.append(execute_block_ip(source_ip, current_mode))
            notes.append(execute_alert_telegram(f"🔥 [HIGH] Đã tự động Block IP: {source_ip}", current_mode))
            
        elif action == "throttle":
            notes.append(execute_throttle_ip(source_ip, current_mode))
            
        elif action == "alert" or action == "alert_operator":
            notes.append(execute_alert_telegram(f"⚠️ Cần SOC Analyst kiểm tra IP: {source_ip}. Lý do: {reason}", current_mode))
            
        elif action == "monitor":
            notes.append(execute_monitor_ip(source_ip, current_mode))
            
        elif action == "ignore":
            pass 
    else:
        notes.append("Responder [SOAR Execution]: Bỏ qua vì không có Source IP hợp lệ.")

    # 4. DATA COLLECTION ĐỂ REVIEW (CÓ INCIDENT ID CHỐNG TRÙNG LẶP)
    if severity in ["high", "critical"] and evidence >= 0.7:
        try:
            os.makedirs("training_data", exist_ok=True)
            log_file_path = "training_data/pending_review.jsonl" 
            
            # correlation_id là incident ID thật — fallback về timestamp nếu không có
            incident_id = (
                state.get("correlation_id")
                or state.get("incident_id")
                or f"INC_{__import__('time').strftime('%Y%m%d_%H%M%S')}"
            )

            raw_ai = state.get("raw_ai_verdict", {})
            training_sample = {
                "incident_id": incident_id,
                "instruction": f"Phân tích log sau và đánh giá mức độ nguy hiểm. Log: {state.get('raw_log')}",
                "input": "",
                "output": json.dumps({
                    "thought_process":   raw_ai.get("thought_process", ""),
                    "reasoning":         raw_ai.get("reasoning", ""),
                    "mitre_mapping":     state.get("mitre_mapping", []),
                    "severity":          severity.upper(),
                    "evidence_strength": state.get("evidence_strength", 0.0),
                    "attack_chain":      state.get("attack_chain_visual", "Unknown")
                }, ensure_ascii=False),
                "human_reviewed": False
            }
            with open(log_file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(training_sample, ensure_ascii=False) + "\n")
            notes.append(f"Responder [Dataset Candidate]: Đã lưu log (Incident ID: {incident_id}) vào file pending_review.jsonl chờ duyệt.")
        except Exception as e:
            notes.append(f"Responder [Auto-Save Error]: Lỗi lưu file -> {e}")

    return {
        "action_taken": action,
        "final_response": action,
        "response_reason": reason,
        "investigation_notes": notes
    }