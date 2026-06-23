import requests
 
class APIClient:
    def __init__(self, base_url, proxy_url=None):
        self.base_url = base_url.rstrip('/')
        self.proxy_url = proxy_url
        self.proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
        self.use_proxy = bool(proxy_url)
        self.session = requests.Session()
        self.default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json, text/html, */*",
            "Content-Type": "application/json",
            "Connection": "keep-alive"
        }
        requests.packages.urllib3.disable_warnings()
 
    def send_request(self, method, endpoint, data=None, json=None, params=None, custom_headers=None, timeout=10):
        if not endpoint.startswith('/'):
            endpoint = '/' + endpoint
 
        full_url = f"{self.base_url}{endpoint}"
 
        headers = self.default_headers.copy()
        if custom_headers:
            headers.update(custom_headers)
 
        proxies_to_use = self.proxies if self.use_proxy else None
 
        try:
            response = self.session.request(
                method=method.upper(),
                url=full_url,
                data=data,
                json=json,
                params=params,
                headers=headers,
                proxies=proxies_to_use,
                verify=False,
                timeout=timeout
            )
            return response
 
        except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError) as e:
            # Proxy lỗi (Burp không bật) → tự động kết nối thẳng
            if self.use_proxy:
                print(f"[⚠️] Proxy không khả dụng, chuyển sang kết nối trực tiếp...")
                self.use_proxy = False
                return self.send_request(method, endpoint, data=data, json=json,
                                         params=params, custom_headers=custom_headers,
                                         timeout=timeout)
            print(f"Lỗi kết nối: {e}")
            return None
 
        except requests.exceptions.Timeout:
            print(f"[⏱️] Timeout: {endpoint}")
            return None
 
        except requests.exceptions.RequestException as e:
            print(f"Lỗi request: {e}")
            return None