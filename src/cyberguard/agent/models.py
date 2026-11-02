from datetime import datetime

from pydantic import BaseModel, Field

from cyberguard.core.models import TelemetryEvent, utcnow


class AgentHeartbeat(BaseModel):
    agent_id: str
    hostname: str
    platform: str
    agent_version: str = "0.9.0"
    timestamp: datetime = Field(default_factory=utcnow)
    events: list[TelemetryEvent]


class AgentStatus(BaseModel):
    agent_id: str
    hostname: str
    platform: str
    agent_version: str
    last_seen: datetime
    state: str
    event_count: int
    incident_count: int
    latest_metrics: dict = Field(default_factory=dict)
