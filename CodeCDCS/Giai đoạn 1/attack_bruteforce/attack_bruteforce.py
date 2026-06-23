import os
import threading 
 
class AttackBruteForce:
    def __init__(self, api_client):
        self.client = api_client
        self.print_lock = threading.Lock()  
 
    def test_brute_force_post(self, endpoint, username_param, password_param, username_file, password_file):
        with self.print_lock:
            print(f"\nBắt đầu thử nghiệm Brute Force tại endpoint: {endpoint}")
            print(f"Sử dụng tham số: {username_param} & {password_param}")

        if not os.path.exists(username_file) or not os.path.exists(password_file):
            with self.print_lock:
                print("Không tìm thấy file username or password để test.")
            return "ERROR_FILE_NOT_FOUND"

        with open(username_file, "r", encoding="utf-8") as f:
            usernames = [line.strip() for line in f if line.strip()]
        with open(password_file, "r", encoding="utf-8") as f:
            passwords = [line.strip() for line in f if line.strip()]

        with self.print_lock:
            print(f"Tổng số kịch bản cần thử nghiệm: {len(usernames) * len(passwords)} cặp credentials.")
            print("-" * 60)

        success_found = False

        for user in usernames:
            for pwd in passwords:
                payload_data = {
                    username_param: user,
                    password_param: pwd
                }

                with self.print_lock:
                    print(f"Thử đăng nhập với tài khoản: {user} | Mật khẩu: {pwd}")
                
                response = self.client.send_request(method="POST", endpoint=endpoint, json=payload_data)

                if response is not None:
                    # --- ĐOẠN ĐÃ THÊM: Xử lý 405 không làm hỏng code ---
                    if response.status_code == 405:
                        with self.print_lock:
                            print(f"--> [405] Endpoint không hỗ trợ POST. Dừng Brute Force tại đây.")
                        return "METHOD_NOT_ALLOWED"
                    # ----------------------------------------------------

                    response_text = response.text.lower()
                    block_signatures = [
                        "too many requests", "rate limit", "blocked",
                        "captcha", "tạm khóa", "quá nhiều yêu cầu"
                    ]
                    is_blocked = (response.status_code == 429) or \
                                 any(sig in response_text for sig in block_signatures)

                    if is_blocked:
                        with self.print_lock:
                            print(f"\nPHÁT HIỆN HỆ THỐNG CÓ BẢO MẬT: Cơ chế Rate Limiting hoặc WAF")
                            print(f"--> Trạng thái: HTTP {response.status_code}")
                            print("Đã dừng Brute Force để tránh bị sót tài khoản hoặc block IP.")
                        return "PROTECTED"

                    if response.status_code == 403:
                        with self.print_lock:
                            print(f"    --> [403] Sai credentials: {user} / {pwd} — tiếp tục thử...")

                    success_signatures = ["success", "token", "jwt", "dashboard", "authenticated"]
                    is_success = any(sig in response_text for sig in success_signatures) or \
                                 response.status_code in [200, 302, 301]

                    if is_success:
                        with self.print_lock:
                            print(f"\n--> ĐÃ TÌM THẤY TÀI KHOẢN HỢP LỆ: {user} / {pwd} (HTTP {response.status_code})")
                        success_found = True
                else:
                    with self.print_lock:
                        print("--> Không nhận được phản hồi từ máy chủ.")

                with self.print_lock:
                    print("-" * 40)

        if success_found:
            return "VULNERABLE"
        else:
            return "SECURE_OR_NOT_FOUND"