from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from .enums import EventCategory, IncidentStatus, Severity


def utcnow() -> datetime:
    return datetime.now(UTC)


class TelemetryEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=utcnow)
    source: str
    category: EventCategory = EventCategory.UNKNOWN
    event_type: str = "generic"
    host: str | None = None
    service: str | None = None
    message: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] | None = None


class Evidence(BaseModel):
    event_id: str | None = None
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    rule_id: str
    title: str
    category: EventCategory
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    summary: str
    root_cause: str
    evidence: list[Evidence]
    analyst_checks: list[str]
    remediation: list[str]
    validation: list[str]
    limitations: list[str]
    mitre_techniques: list[str] = Field(default_factory=list)
    correlation_key: str


class Incident(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    title: str
    category: EventCategory
    severity: Severity
    status: IncidentStatus = IncidentStatus.OPEN
    confidence: float
    summary: str
    root_cause: str
    evidence: list[Evidence]
    analyst_checks: list[str]
    remediation: list[str]
    validation: list[str]
    limitations: list[str]
    mitre_techniques: list[str] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list)
    correlation_key: str
    event_count: int = 0
