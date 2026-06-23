def convert_ai_result(ai_response):

    if not ai_response:
        return {}

    if "results" not in ai_response:
        return ai_response

    if len(ai_response["results"]) == 0:
        return {}

    result = ai_response["results"][0]

    return {

        "severity":
            result.get("severity", "").lower(),

        "confidence":
            result.get("confidence"),

        "incident_id":
            result.get("incident_id"),

        "mitre":
            result.get("mitre_techniques", []),

        "attack_chain":
            [
                result.get(
                    "attack_chain_stage",
                    "unknown"
                )
            ],

        "timeline":
            [
                {
                    "timestamp":
                        item.get(
                            "event_timestamp"
                        ),

                    "name":
                        item.get(
                            "event_type"
                        ),

                    "severity":
                        item.get(
                            "severity"
                        ),

                    "stage":
                        item.get(
                            "attack_chain_stage"
                        ),

                    "source_ip":
                        item.get(
                            "source_ip"
                        )

                }

                for item in result.get(
                    "attack_timeline",
                    []
                )
            ],

        "summary":

            result.get(
                "raw_ai_verdict",
                {}
            ).get(
                "reasoning",
                ""
            ),

        "profile":

            (
                result.get(
                    "raw_ai_verdict",
                    {}
                ).get(
                    "thought_process"
                )

                or

                result.get(
                    "raw_ai_verdict",
                    {}
                ).get(
                    "reasoning"
                )

                or

                "No profile available."
            ),

        "phase": {

            "current_phase": 1,

            "phase_name":

                result.get(
                    "attack_chain_stage"
                ),

            "attack_progress":

                result.get(
                    "attack_chain_stage"
                )

        },

        "action_taken":

            result.get(
                "action_taken"
            ),

        "response_actions": [

            result.get(
                "action_taken"
            ) or "No action"

        ],

        "processing_time_ms":

            result.get(
                "processing_time_ms"
            ),

        "investigation_notes":

            result.get(
                "investigation_notes",
                []
            ),

        "siem_alerts": [],
    }

if __name__ == "__main__":

    sample = {
        "results": [
            {
                "severity": "HIGH",
                "confidence": 0.92,
                "incident_id": "abc123",
                "attack_chain_stage": "execution",
                "mitre_techniques": [
                    "T1059"
                ],
                "action_taken": "BLOCK",
                "attack_timeline": [],
                "raw_ai_verdict": {
                    "reasoning": "test",
                    "thought_process": "demo"
                }
            }
        ]
    }

    print(
        convert_ai_result(sample)
    )
