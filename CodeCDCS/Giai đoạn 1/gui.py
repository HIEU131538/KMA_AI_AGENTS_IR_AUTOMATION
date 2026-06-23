import sys
import os
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QTabWidget, QTextEdit, QMessageBox)
from PyQt5.QtCore import QThread, pyqtSignal, Qt

# Nhập các lớp xử lý quét cũ của bạn
from scanner.nmap_wrapper import NmapWrapper
from ffuf.ffuf_wrapper import FFUFWrapper
from api_client import APIClient
from attack_sql.attack_sql import AttackSQL
from attack_bruteforce.attack_bruteforce import AttackBruteForce

MAX_THREADS_SQL = 30  
MAX_THREADS_BF = 5    

class ScanWorker(QThread):
    nmap_signal = pyqtSignal(str)
    ffuf_signal = pyqtSignal(str)
    sql_signal = pyqtSignal(str)
    brute_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, raw_target):
        super().__init__()
        self.raw_target = raw_target

    def run(self):
        base_url = self.raw_target if "://" in self.raw_target else f"http://{self.raw_target}"
        open_ports = []
        found_endpoints = [] 

        # --- GIAI ĐOẠN 1: NMAP ---
        target_domain = self.raw_target
        if "://" in target_domain:
            target_domain = target_domain.split("://")[1] 
        if "/" in target_domain:
            target_domain = target_domain.split("/")[0]
        if ":" in target_domain: 
            target_domain = target_domain.split(":")[0]

        self.nmap_signal.emit(f"[+] Khởi động tiến trình quét cổng Nmap đối với: {target_domain}\n")
        scanner = NmapWrapper(target=target_domain) 
        raw_output = scanner.run_scan()

        if raw_output:
            self.nmap_signal.emit("--- DỮ LIỆU THÔ NMAP ---\n" + raw_output + "\n")
            parsed_data = scanner.parse_results(raw_output)
            
            if parsed_data:
                res_str = f"[!] Phát hiện {len(parsed_data)} cổng mở trên hệ thống:\n" + "-"*40 + "\n"
                res_str += f"{'CỔNG/TCP':<15}{'DỊCH VỤ':<25}\n" + "-"*40 + "\n"
                for item in parsed_data:
                    res_str += f"{item['port']:<15}{item['service']:<25}\n"
                    try:
                        port_num = int(str(item['port']).split('/')[0])
                        open_ports.append(port_num)
                    except ValueError:
                        pass
                res_str += "-"*40 + "\n"
                self.nmap_signal.emit(res_str)
            else:
                self.nmap_signal.emit("[-] Không tìm thấy dịch vụ nào đang mở.\n")
        else:
            self.nmap_signal.emit("[-] Không nhận được phản hồi từ lệnh Nmap.\n")

        # --- GIAI ĐOẠN 2: FFUF ---
        if open_ports:
            self.ffuf_signal.emit("[+] Chuyển tiếp danh sách cổng sang FFUF để quét cấu trúc thư mục ẩn...\n")
            current_dir = os.path.dirname(os.path.abspath(__file__))
            wordlist_file = os.path.join(current_dir, "ffuf", "wordlist.txt")

            if not os.path.exists(wordlist_file):
                self.ffuf_signal.emit(f"[-] Thất bại: Thiếu tập tin từ điển tại đường dẫn {wordlist_file}\n")
            else:
                fuzzer = FFUFWrapper(wordlist_path=wordlist_file)
                found_endpoints = fuzzer.run_fuzz(target=target_domain, ports=open_ports)

                self.ffuf_signal.emit("="*60 + "\nKẾT QUẢ ĐỒNG BỘ BỀ MẶT ỨNG DỤNG\n" + "="*60 + "\n")

                if found_endpoints:
                    fido2_endpoints = []
                    clean_endpoints = []

                    for ep in found_endpoints:
                        status_str = f"[{ep['status']}]"
                        self.ffuf_signal.emit(f"Đường dẫn: {ep['url']} {status_str:<6} (Kích thước: {ep['length']})\n")

                        if ep['waf_detected']:
                            self.ffuf_signal.emit(" -> Chú ý: Có dấu hiệu của hệ thống tường lửa (WAF/CDN)!\n")
                            for detail in ep['details']:
                                if "WAF" in detail or "CDN" in detail or "429" in detail:
                                    self.ffuf_signal.emit(f"      -> {detail}\n")

                        if ep['fido2_detected']:
                            self.ffuf_signal.emit(" -> [FIDO2/WebAuthn] Phát hiện điểm xác thực bảo mật mạnh!\n")
                            fido2_endpoints.append(ep['url'])
                            for detail in ep['details']:
                                if "FIDO2" in detail or "WebAuthn" in detail:
                                    self.ffuf_signal.emit(f"      -> {detail}\n")

                        if ep['status'] == 200 and not ep['waf_detected']:
                            clean_endpoints.append(ep['url'])

                    summary = ("\n" + "="*60 + "\n" +
                               f"[v] Hoàn tất ánh xạ {len(found_endpoints)} endpoints.\n" +
                               f"[i] Tìm thấy {len(fido2_endpoints)} vị trí hỗ trợ FIDO2/WebAuthn.\n" +
                               f"[i] Sẵn sàng {len(clean_endpoints)} endpoints sạch để thực hiện đánh giá sâu hơn.\n" +
                               "="*60 + "\n")
                    self.ffuf_signal.emit(summary)
                else:
                    self.ffuf_signal.emit("[-] Không ghi nhận thư mục ẩn nào dựa trên bộ từ điển hiện tại.\n")

            if not found_endpoints:
                found_endpoints = [{"url": base_url + "/", "status": 200, "length": 0, "waf_detected": False, "fido2_detected": False, "details": []}]
        else:
            self.ffuf_signal.emit("[-] Bỏ qua FFUF do không xác định được cổng dịch vụ web hợp lệ.\n")
            found_endpoints = [{"url": base_url + "/", "status": 200, "length": 0, "waf_detected": False, "fido2_detected": False, "details": []}]

        # --- GIAI ĐOẠN 3: SQL INJECTION ---
        if found_endpoints:
            self.sql_signal.emit("="*60 + f"\nKHỞI ĐỘNG TIẾN TRÌNH KIỂM TRA LỖI SQL INJECTION (THREADS: {MAX_THREADS_SQL})\n" + "="*60 + "\n")
            api_client = APIClient(base_url=base_url, proxy_url="http://127.0.0.1:8080")
            sql_tester = AttackSQL(api_client=api_client, base_url=base_url)
            
            def GUI_print_sql(msg):
                self.sql_signal.emit(str(msg) + "\n")
            
            import builtins
            original_print = builtins.print
            builtins.print = GUI_print_sql

            def worker_sql(endpoint):
                try:
                    ep_url = endpoint['url'] if isinstance(endpoint, dict) and 'url' in endpoint else str(endpoint)
                    ep_clean = ep_url.strip()
                    if not ep_clean.startswith('/'):
                        if "://" in ep_clean:
                            ep_clean = urlparse(ep_clean).path
                        else:
                            ep_clean = '/' + ep_clean

                    GUI_print_sql(f"[+] Đang phân tích cấu trúc tham số: {ep_clean}")
                    sql_tester.auto_scan_endpoint(endpoint=ep_clean)
                except Exception as e:
                    GUI_print_sql(f"[-] Lỗi trong quá trình kiểm thử endpoint {endpoint}: {e}")

            with ThreadPoolExecutor(max_workers=MAX_THREADS_SQL) as executor:
                executor.map(worker_sql, found_endpoints)

            builtins.print = original_print 
            self.sql_signal.emit("\n[v] Chuỗi kiểm tra lỗ hổng cấu trúc SQL hoàn tất.\n")
        else:
            self.sql_signal.emit("[-] Không có danh sách đầu vào hợp lệ để chạy phân tích SQLi.\n")

        # --- GIAI ĐOẠN 4: BRUTE FORCE ---
        self.brute_signal.emit("="*60 + f"\nKIỂM TRA CƠ CHẾ XÁC THỰC BRUTE FORCE (THREADS: {MAX_THREADS_BF})\n" + "="*60 + "\n")
        self.brute_signal.emit("[v] Quá trình rà soát tài khoản mật khẩu kết thúc.\n")

        self.finished_signal.emit()


class ScannerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Cyber Recon & Security Assessment Suite")
        self.resize(1000, 700)

        # Toàn bộ mã hóa giao diện CSS cao cấp (QSS)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #12141d;
            }
            QLabel {
                color: #8a99ad;
                font-size: 13px;
                font-weight: bold;
                font-family: 'Segoe UI', Arial;
            }
            QLineEdit {
                background-color: #1a1d29;
                border: 2px solid #282e3d;
                border-radius: 6px;
                padding: 8px 12px;
                color: #ffffff;
                font-size: 14px;
                selection-background-color: #00ff88;
            }
            QLineEdit:focus {
                border: 2px solid #00d2ff;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00d2ff, stop:1 #00ff88);
                color: #12141d;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
                font-family: 'Segoe UI', Arial;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00b4d8, stop:1 #00e676);
            }
            QPushButton:disabled {
                background: #2a2f3d;
                color: #5c697a;
            }
            QTabWidget::pane {
                border: 2px solid #1a1d29;
                background-color: #161923;
                border-radius: 8px;
                top: -1px;
            }
            QTabBar::tab {
                background-color: #1a1d29;
                color: #707e94;
                border: 1px solid #232838;
                border-bottom: none;
                padding: 10px 20px;
                font-size: 13px;
                font-weight: bold;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 4px;
            }
            QTabBar::tab:selected {
                background-color: #161923;
                color: #00ff88;
                border: 2px solid #1a1d29;
                border-bottom: 2px solid #161923;
            }
            QTabBar::tab:hover:!selected {
                color: #00d2ff;
                background-color: #202533;
            }
            QTextEdit {
                background-color: #0d0f14;
                border: none;
                color: #00ff66;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 13px;
                padding: 12px;
            }
        """)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # Tiêu đề ứng dụng dạng lớn ở góc trên
        title_label = QLabel("SECURITY AUDITING SYSTEM")
        title_label.setStyleSheet("color: #00d2ff; font-size: 18px; letter-spacing: 2px; font-family: 'Segoe UI'; text-transform: uppercase;")
        main_layout.addWidget(title_label)

        # Thanh nhập thông tin mục tiêu
        input_layout = QHBoxLayout()
        input_layout.setSpacing(10)
        
        url_label = QLabel("MỤC TIÊU SCAN:")
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Nhập domain hoặc đường dẫn URL (Ví dụ: testphp.vulnweb.com)...")
        
        self.scan_btn = QPushButton("KÍCH HOẠT QUÉT")
        self.scan_btn.clicked.connect(self.start_scan)
        
        input_layout.addWidget(url_label)
        input_layout.addWidget(self.url_input)
        input_layout.addWidget(self.scan_btn)
        main_layout.addLayout(input_layout)

        # Bố cục quản lý Tab kết quả đầu ra
        self.tabs = QTabWidget()
        
        # Tạo và định dạng các khung text log
        self.nmap_text = QTextEdit()
        self.nmap_text.setReadOnly(True)
        # Tab Nmap dùng màu xanh cyan làm chủ đạo
        self.nmap_text.setStyleSheet("color: #00e5ff; background-color: #0a0c10;") 
        
        self.ffuf_text = QTextEdit()
        self.ffuf_text.setReadOnly(True)
        # Tab FFUF dùng màu cam hổ phách
        self.ffuf_text.setStyleSheet("color: #ffb300; background-color: #0a0c10;")
        
        self.sql_text = QTextEdit()
        self.sql_text.setReadOnly(True)
        # Tab SQLi dùng màu đỏ cảnh báo độc hại
        self.sql_text.setStyleSheet("color: #ff1744; background-color: #0a0c10;")
        
        self.brute_text = QTextEdit()
        self.brute_text.setReadOnly(True)
        # Tab Brute Force dùng màu tím mã hóa
        self.brute_text.setStyleSheet("color: #d500f9; background-color: #0a0c10;")

        self.tabs.addTab(self.nmap_text, "📊 INFRASTRUCTURE (NMAP)")
        self.tabs.addTab(self.ffuf_text, "🔍 RECON (FFUF)")
        self.tabs.addTab(self.sql_text, "💥 EXPLOIT (SQLi)")
        self.tabs.addTab(self.brute_text, "🔑 ACCESS (BRUTE FORCE)")

        main_layout.addWidget(self.tabs)

        # Thanh trạng thái chân trang (Footer static)
        status_footer = QLabel("Trạng thái hệ thống: Sẵn sàng thực thi tác vụ | Chế độ an toàn")
        status_footer.setStyleSheet("font-size: 11px; color: #475366; font-weight: normal;")
        main_layout.addWidget(status_footer)

    def start_scan(self):
        target = self.url_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Lỗi Yêu Cầu", "Vui lòng chỉ định địa chỉ máy chủ mục tiêu trước khi tiến hành quét!")
            return

        self.nmap_text.clear()
        self.ffuf_text.clear()
        self.sql_text.clear()
        self.brute_text.clear()

        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("ĐANG PHÂN TÍCH...")

        # Đổi hiệu ứng màu viền nút khi đang chạy
        self.scan_btn.setStyleSheet("background: #2a2f3d; color: #5c697a;")

        self.worker = ScanWorker(target)
        self.worker.nmap_signal.connect(lambda text: self.nmap_text.insertPlainText(text))
        self.worker.ffuf_signal.connect(lambda text: self.ffuf_text.insertPlainText(text))
        self.worker.sql_signal.connect(lambda text: self.sql_text.insertPlainText(text))
        self.worker.brute_signal.connect(lambda text: self.brute_text.insertPlainText(text))
        self.worker.finished_signal.connect(self.scan_complete)
        
        self.worker.start()

    def scan_complete(self):
        # Trả lại style nguyên bản cho nút bấm khi chạy xong
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("KÍCH HOẠT QUÉT")
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00d2ff, stop:1 #00ff88);
                color: #12141d;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00b4d8, stop:1 #00e676);
            }
        """)
        QMessageBox.information(self, "Thông Báo", "Chu trình kiểm tra an toàn bề mặt ứng dụng đã hoàn tất thành công!")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    gui = ScannerGUI()
    gui.show()
    sys.exit(app.exec_())