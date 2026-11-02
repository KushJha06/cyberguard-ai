from pydantic import BaseModel, Field

from cyberguard.analysis.diagnostics import DiagnosticSummary
from cyberguard.analysis.manifest import AnalysisManifest
from cyberguard.core.enums import IncidentStatus
from cyberguard.core.models import Incident, TelemetryEvent


class EventBatch(BaseModel):
    events: list[TelemetryEvent] = Field(min_length=1)


class IngestResponse(BaseModel):
    accepted_events: int
    incidents: list[Incident]
    diagnosis: DiagnosticSummary | None = None
    manifest: AnalysisManifest | None = None
    processing_ms: float = 0
    request_id: str | None = None


class HealthResponse(BaseModel):
    status: str
    version: str
    rules: int
    adapters: list[str]
    stored_events: int


class StatusUpdate(BaseModel):
    status: IncidentStatus


class Capability(BaseModel):
    id: str
    name: str


class StatsResponse(BaseModel):
    events: int
    incidents: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    generated_at: str


class ErrorResponse(BaseModel):
    detail: str
    request_id: str | None = None


class DatasetResponse(BaseModel):
    id: str
    name: str
    provider: str
    homepage: str
    download_url: str
    license_url: str
    domains: list[str]
    formats: list[str]
    size_note: str
    license_note: str
    recommended_use: str
    adapter_status: str
    upload_instructions: str
    coverage: list[str]
