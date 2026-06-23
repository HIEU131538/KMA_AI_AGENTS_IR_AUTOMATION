import subprocess
import re

class NmapWrapper:

    def __init__(self, target):
        self.target = target

    def run_scan(self):
        try:
            cmd = [
                "nmap",
                "-sV",          
                "--open",
                "-F",  
                "-T4",  
                "-n",   
                "--version-intensity", "0",  # 💡 Ép Nmap giảm cường độ quét sâu để đỡ sinh ra SF:
                self.target
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=300
            )

            raw_data = result.stdout
            
            # 💡 Dùng Regex lọc bỏ toàn bộ các dòng chứa dữ liệu không xác định (bắt đầu bằng SF:)
            clean_lines = [line for line in raw_data.splitlines() if not re.match(r'^\s*SF:', line)]
            clean_data = "\n".join(clean_lines)

            return clean_data

        except FileNotFoundError:
            print("Không tìm thấy Nmap trên hệ thống!")
            return None
        except subprocess.TimeoutExpired:
            print("Quét Nmap bị timeout!")
            return None
        except subprocess.CalledProcessError as e:
            print("Nmap trả về lỗi:")
            print(e.stderr)
            return None
        except Exception as e:
            print(f"Lỗi không xác định: {e}")
            return None

    def parse_results(self, raw_data):
        if not raw_data:
            return []

        results = []
        
        pattern = r"(\d+)/(tcp|udp)\s+open\s+(.+)$"

        for line in raw_data.splitlines():
            match = re.search(pattern, line)
            if match:
                port = match.group(1)
                protocol = match.group(2)
                service_full = match.group(3).strip() 
                service_name = service_full.split()[0] if service_full else "unknown"

                results.append({
                    "port": int(port),
                    "protocol" : protocol,
                    "service": service_name
                })
    
        return results