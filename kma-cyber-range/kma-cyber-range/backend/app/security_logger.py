import json
import os

from datetime import datetime, timezone
from uuid import uuid4

AUTH_LOG = "/var/log/kma-auth/auth.log"

def write_auth_event(
    event,
    actor=None,
    target=None,
    result=None,
    ip=None,
    details=None,
    severity="info"
):
    os.makedirs(
        os.path.dirname(AUTH_LOG),
        exist_ok=True
    )

    record = {
        "event_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "auth",
        "severity": severity,
        "event": event,
        "actor": actor,
        "target": target,
        "result": result,
        "ip": ip,
        "details": details
    }

    with open(AUTH_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
