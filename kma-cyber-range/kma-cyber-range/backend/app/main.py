import threading
import time as _time

from app.init_db import init_database
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.logging_middleware import register_logging_middleware
from app.routes import admin, auth, employees, tools

app = FastAPI(
    title="KMA HR Management API",
    description="Backend API for KMA Cyber Range",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

register_logging_middleware(app)

app.include_router(auth.router)
app.include_router(employees.router)
app.include_router(tools.router)
app.include_router(admin.router)


@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "ok",
        "service": "kma-app",
        "ip": "172.20.0.3"
    }


def _auto_bridge_loop():
    """Background thread: đọc log mới và tự động đẩy sang AI Agent mỗi 30 giây."""
    from app.bridge_service import load_normalized_logs
    from app.bridge_client import send_batch_logs

    _time.sleep(15)  # chờ app khởi động xong hoàn toàn
    print("[AutoBridge] Scheduler started — polling every 30s.")

    while True:
        try:
            logs = load_normalized_logs()
            logs = [l for l in logs if l and l.get("event_type") != "web_access"]
            if logs:
                logs = logs[:20]
                print(f"[AutoBridge] Sending {len(logs)} security log(s) to AI Agent...")
                result = send_batch_logs(logs, reset_memory=False)
                if "error" in result:
                    print(f"[AutoBridge] AI Agent error: {result['error']}")
                else:
                    llm_count = result.get("pre_filter_stats", {}).get("llm_analyzed", "?")
                    print(f"[AutoBridge] Done. LLM analyzed: {llm_count}")
            else:
                print("[AutoBridge] No new security logs.")
        except Exception as exc:
            print(f"[AutoBridge] Error: {exc}")

        _time.sleep(30)


@app.on_event("startup")
def on_startup():
    init_database()
    t = threading.Thread(target=_auto_bridge_loop, daemon=True, name="AutoBridge")
    t.start()
    print("[Startup] AutoBridge scheduler started (interval: 30s).")
