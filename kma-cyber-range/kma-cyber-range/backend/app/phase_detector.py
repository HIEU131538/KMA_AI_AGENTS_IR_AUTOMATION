from app.attack_knowledge import (
    ATTACK_PHASES
)

def detect_attack_phase(threats):

    attacks = [
        x.get("attack")
        for x in threats
    ]

    highest_phase = 0

    for phase_id, phase in ATTACK_PHASES.items():

        for indicator in phase["indicators"]:

            if indicator in attacks:

                highest_phase = max(
                    highest_phase,
                    phase_id
                )

    if highest_phase == 0:

        return {
            "current_phase": 0,
            "phase_name": "Unknown",
            "attack_progress": "0%"
        }

    return {
        "current_phase": highest_phase,
        "phase_name":
            ATTACK_PHASES[
                highest_phase
            ]["name"],

        "attack_progress":
            f"{highest_phase * 20}%"
    }
