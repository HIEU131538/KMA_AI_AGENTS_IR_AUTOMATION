from datetime import datetime

from app.memory.incident_store import (
    load_incidents,
    save_incidents
)

def build_incident(
    attack_chain,
    severity
):

    incidents = load_incidents()

    if severity not in [
        "high",
        "critical"
    ]:
        return None

    if incidents:

       last_incident = incidents[-1]

       if (
           last_incident.get("attack_chain")
           ==
           attack_chain
       ):

           changed = False

           if last_incident.get("severity") != severity:

               last_incident["severity"] = severity
               changed = True

           last_incident["events"] = len(
               attack_chain
           )

           last_incident["attack_chain"] = (
               attack_chain
           )

           if changed:

              save_incidents(
                  incidents
              )

           return last_incident

    incident_id = (
        f"INC-{len(incidents)+1:03d}"
    )

    incident = {
        "incident_id": incident_id,
        "created_at": datetime.utcnow().isoformat(),
        "title": "Multi Stage Attack",
        "severity": severity,
        "events": len(attack_chain),
        "attack_chain": attack_chain
    }

    incidents.append(
        incident
    )

    save_incidents(
        incidents
    )

    return incident
