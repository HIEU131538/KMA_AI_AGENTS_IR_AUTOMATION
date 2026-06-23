import json
from pathlib import Path

INCIDENT_FILE = "/var/log/kma-security/incidents.json"


def load_incidents():

    path = Path(INCIDENT_FILE)

    if not path.exists():
        return []

    try:
        return json.loads(
            path.read_text()
        )
    except Exception:
        return []


def save_incidents(data):

    Path(INCIDENT_FILE).write_text(
        json.dumps(
            data,
            indent=2
        )
    )
