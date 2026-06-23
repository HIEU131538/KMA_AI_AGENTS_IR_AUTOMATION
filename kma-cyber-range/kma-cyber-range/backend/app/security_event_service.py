import json
import os

from datetime import datetime, timezone
from uuid import uuid4

SECURITY_EVENT_LOG = "/var/log/kma-security/events.log"


def write_security_event(
    event,
    severity="info",
    user=None,
    ip=None,
    details=None,
    source="backend"
):
    os.makedirs(
        os.path.dirname(SECURITY_EVENT_LOG),
        exist_ok=True
    )

    record = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "event_id": str(uuid4()),
        "source": source,
        "severity": severity,
        "event": event,
        "user": user,
        "ip": ip,
        "details": details
    }

    with open(
        SECURITY_EVENT_LOG,
        "a",
        encoding="utf-8"
    ) as f:
        f.write(
            json.dumps(record)
            + "\n"
        )

