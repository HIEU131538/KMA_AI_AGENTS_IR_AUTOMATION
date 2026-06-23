import os
import time
import json

from datetime import datetime

LOG_FILES = [
    "/logs/app/app.log",
    "/logs/threat/threat.log",
    "/logs/waf/audit.log",
    "/logs/nginx/access.log",
    "/logs/nginx/error.log",
]

ALERT_FILE = "/logs/siem/alerts.json"

def write_alert(
    rule,
    level,
    source
):

    alert = {
        "timestamp":
            datetime.utcnow().isoformat(),

        "rule":
            rule,

        "level":
            level,

        "source":
            source
    }

    with open(
        ALERT_FILE,
        "a",
        encoding="utf-8"
    ) as f:

        f.write(
            json.dumps(alert)
            + "\n"
        )

def open_log_file(path):
    if not os.path.exists(path):
        return None

    f = open(path, "r", encoding="utf-8", errors="ignore")

    # Chỉ đọc log mới phát sinh sau khi SIEM chạy
    f.seek(0, os.SEEK_END)

    return f


def main():
    print("[kma-siem] Lightweight log collector started", flush=True)
    print("[kma-siem] Watching shared log volume: /logs", flush=True)

    handlers = {}

    while True:
        for path in LOG_FILES:
            handler = handlers.get(path)

            if handler is None:
                handler = open_log_file(path)

                if handler is not None:
                    handlers[path] = handler
                    print(f"[kma-siem] Now watching: {path}", flush=True)
                else:
                    continue

            line = handler.readline()

            if line:
                print(
                    f"[kma-siem] {path}: {line.strip()}",
                    flush=True
                )

                lower_line = line.lower()

                if (
                    "mass_assignment_role_escalation"
                    in lower_line
                ):

                    write_alert(
                        "Privilege Escalation",
                        12,
                        path
                    )

                if (
                    "ssrf"
                    in lower_line
                ):

                    write_alert(
                        "SSRF Attempt",
                        10,
                        path
                    )

                if (
                    "employee_export"
                    in lower_line
                ):

                    write_alert(
                        "Data Exfiltration",
                        14,
                        path
                    )

        time.sleep(1)


if __name__ == "__main__":
    main()
