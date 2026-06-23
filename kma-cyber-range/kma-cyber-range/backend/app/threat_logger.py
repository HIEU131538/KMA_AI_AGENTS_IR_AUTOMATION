import json
import os

from datetime import datetime, timezone
from uuid import uuid4

THREAT_LOG = "/var/log/kma-threat/threat.log"

def write_threat_event(
    attack,
    severity,
    user=None,
    ip=None,
    mitre=None,
    status="detected"
):
    os.makedirs(
        os.path.dirname(THREAT_LOG),
        exist_ok=True
    )

    record = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "event_id": str(uuid4()),
        "source": "backend",
        "attack": attack,
        "severity": severity,
        "user": user,
        "ip": ip,
        "mitre": mitre,
        "status": status
    }

    with open(
        THREAT_LOG,
        "a",
        encoding="utf-8"
    ) as f:
        f.write(
            json.dumps(record)
            + "\n"
        )

