import os
import sys

from api_client import APIClient
from attack_sql.attack_sql import AttackSQL
from attack_bruteforce.attack_bruteforce import AttackBruteForce

TARGET_ENDPOINT = "/auth/login"

if __name__ == "__main__":
    if len(sys.argv) > 1:
        raw_target = sys.argv[1].strip()
    else:
        raw_target = input("Nhập địa chỉ target (VD: 100.126.121.94:8000): ").strip()

    base_url = raw_target if "://" in raw_target else f"http://{raw_target}"

    print(f"\n{'='*60}")
    print(f"[*] TARGET : {base_url}")
    print(f"[*] ENDPOINT: {TARGET_ENDPOINT}")
    print(f"{'='*60}\n")

    # Không dùng proxy — kết nối thẳng vào target
    api_client = APIClient(base_url=base_url, proxy_url=None)

    # =====================================================================
    # GIAI ĐOẠN 1: BRUTE FORCE /auth/login
    # =====================================================================
    print(f"[>>>] BRUTE FORCE vào {TARGET_ENDPOINT}")
    print("-" * 60)

    bf_tester = AttackBruteForce(api_client=api_client)

    current_dir = os.path.dirname(os.path.abspath(__file__))
    user_list = os.path.join(current_dir, "attack_bruteforce", "username.txt")
    pwd_list  = os.path.join(current_dir, "attack_bruteforce", "password.txt")

    bf_result = bf_tester.test_brute_force_post(
        endpoint=TARGET_ENDPOINT,
        username_param="username",
        password_param="password",
        username_file=user_list,
        password_file=pwd_list
    )
    print(f"\n[+] Kết quả Brute Force: {bf_result}")

    # =====================================================================
    # GIAI ĐOẠN 2: SQL INJECTION /auth/login
    # =====================================================================
    print(f"\n[>>>] SQL INJECTION vào {TARGET_ENDPOINT}")
    print("-" * 60)

    sql_tester = AttackSQL(api_client=api_client, base_url=base_url)

    sql_tester.test_sqli(
        method="POST",
        endpoint=TARGET_ENDPOINT,
        param_name="username",
        static_data={"password": "anything"},
        is_json=True
    )

    print(f"\n{'='*60}")
    print("[*] Hoàn tất. Kiểm tra AI Agent dashboard để xem kết quả phân tích.")
    print(f"{'='*60}")
