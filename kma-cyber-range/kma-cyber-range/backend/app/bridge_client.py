import json
import os
import requests

AI_AGENT_URL = os.getenv (
    "AI_AGENT_URL",
    "http://100.116.98.92:8000"
)

def send_single_log(
    log_data
):

    payload = {
        "raw_log": log_data
    }

    try:

        response = requests.post(
            f"{AI_AGENT_URL}/analyze",
            json=payload,
            timeout=5
        )

        return response.json()

    except Exception as e:

        return {
            "error": str(e)
        }

def send_batch_logs(
    logs,
    reset_memory=False
):

    payload = {
        "reset_memory":
            reset_memory,

        "logs":
            logs
    }

    try:

        print("=" * 80)
        print("Payload gửi sang AI Agent")
        print("=" * 80)

        print(json.dumps(payload, indent=2))

        print("=" * 80)
        print(f"[Bridge] Sending {len(logs)} logs")
        print("=" * 80)

        response = requests.post(
            f"{AI_AGENT_URL}/analyze/batch",
            json=payload,
            timeout=300
        )

        print("=" * 80)
        print("AI STATUS:", response.status_code)
        print("AI HEADERS:", response.headers)
        print("AI TEXT:")
        print(response.text)
        print("=" * 80)

        return response.json()

    except Exception as e:

        return {
            "error": str(e)
        }

def reset_ai_memory():

    try:

        response = requests.post(
            f"{AI_AGENT_URL}/reset",
            timeout=10
        )

        return response.json()

    except Exception as e:

        return {
            "error": str(e)
        }
