import subprocess
import json
import os
import requests
from concurrent.futures import ThreadPoolExecutor

class FFUFWrapper:
    def __init__(self, wordlist_path):
        self.wordlist = wordlist_path
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.ffuf_binary = os.path.join(current_dir, "ffuf.exe")

    def run_fuzz(self, target, ports, method="GET", data=None):
        all_results = []
        executable = self.ffuf_binary if os.path.exists(self.ffuf_binary) else "ffuf"

        for port in ports:
            protocol = "https" if port == 443 else "http"
            base_url = f"{protocol}://{target}:{port}"
            output_file = f"ffuf_temp_{port}.json"

            cmd = [executable, "-u", f"{base_url}/FUZZ", "-w", self.wordlist, 
                   "-X", "GET", "-o", output_file, "-of", "json", "-mc", "200,405"]
            
            subprocess.run(cmd, capture_output=True, text=True)

            if os.path.exists(output_file):
                all_results.extend(self.parse_ffuf_results(output_file))
                os.remove(output_file)
        return all_results

    def _analyze_single(self, res):
        url = res.get('url', '')
        status = res.get('status', 0)
        
        # LOGIC MỚI: Nếu là 405, ta "ép" nó thành POST để đánh giá nội dung
        target_method = 'POST' if status == 405 else 'GET'
        
        waf_detected, fido2_detected = False, False
        reasons = []

        try:
            # Dùng method đã quyết định ở trên để gọi lại endpoint
            response = requests.request(target_method, url, timeout=5, verify=False)
            resp_text = response.text.lower()
            
            # Kiểm tra FIDO2 (Cả URL và Body)
            if any(kw in url.lower() for kw in ['fido2', 'webauthn']) or \
               any(kw in resp_text for kw in ['challenge', 'pubkeycredparams', 'rp', 'webauthn']):
                fido2_detected = True
                reasons.append("FIDO2/WebAuthn endpoint detected via " + target_method)
            
            # Kiểm tra WAF
            if any(kw in resp_text for kw in ['access denied', 'cloudflare', 'blocked']):
                waf_detected = True
                reasons.append("WAF content detected")
                
        except: pass

        return {
            "url": url, "status": status, "length": res.get('length', 0),
            "waf_detected": waf_detected, "fido2_detected": fido2_detected, "details": reasons
        }

    def parse_ffuf_results(self, json_file):
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return [self._analyze_single(r) for r in data.get('results', [])]