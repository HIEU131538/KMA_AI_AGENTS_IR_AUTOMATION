from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="KMA AI SOC Agent",
    description="Placeholder API for AI Agent integration",
    version="0.1.0"
)


class BlockIPRequest(BaseModel):
    ip: str
    reason: str | None = None


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "kma-ai-agent",
        "ip": "172.20.0.5"
    }


@app.post("/actions/block-ip")
def block_ip(data: BlockIPRequest):
    return {
        "action": "block_ip",
        "status": "simulated",
        "ip": data.ip,
        "reason": data.reason
    }
