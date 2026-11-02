import secrets
import time
from pathlib import Path
from tempfile import NamedTemporaryFile
from uuid import uuid4

from fastapi import FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

from cyberguard.agent.models import AgentHeartbeat, AgentStatus
from cyberguard.analysis.diagnostics import PreflightReport, diagnose, run_preflight
from cyberguard.analysis.manifest import build_manifest
from cyberguard.config import get_settings
from cyberguard.core.enums import IncidentStatus, Severity
from cyberguard.core.models import Incident
from cyberguard.core.service import TriageService
from cyberguard.datasets.catalog import list_datasets
from cyberguard.datasets.demo import complete_demo_events
from cyberguard.plugins import PLUGIN_API_VERSION, PluginInfo

from .schemas import (
    Capability,
    DatasetResponse,
    EventBatch,
    HealthResponse,
    IngestResponse,
    StatsResponse,
    StatusUpdate,
)

VERSION = "0.9.0"
settings = get_settings()
app = FastAPI(
    title="CyberGuard AI",
    version=VERSION,
    description="Local-first diagnostics and cybersecurity triage API",
    docs_url="/docs",
    redoc_url="/redoc",
)
app.add_middleware(GZipMiddleware, minimum_size=1_000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[item.strip() for item in settings.cors_origins.split(",")],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Content-Type", "X-Request-ID"],
)
service = TriageService()


@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = request.headers.get(settings.request_id_header) or str(uuid4())
    request.state.request_id = request_id
    started = time.perf_counter()
    response = await call_next(request)
    response.headers[settings.request_id_header] = request_id
    response.headers["X-Process-Time-Ms"] = f"{(time.perf_counter() - started) * 1000:.2f}"
    return response


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={"detail": str(exc), "request_id": getattr(request.state, "request_id", None)},
    )


@app.get("/health", response_model=HealthResponse, tags=["operations"])
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        version=VERSION,
        rules=len(service.rules.rule_ids),
        adapters=service.adapters.names,
        stored_events=service.store.event_count(),
    )


@app.get("/api/v1/preflight", response_model=PreflightReport, tags=["operations"])
def preflight() -> PreflightReport:
    return run_preflight()


@app.get("/api/v1/stats", response_model=StatsResponse, tags=["operations"])
def stats() -> dict:
    return service.store.stats()


@app.get("/api/v1/rules", response_model=list[Capability], tags=["operations"])
def rules() -> list[Capability]:
    return [Capability(id=rule_id, name=title) for rule_id, title in service.rules.capabilities]


@app.get("/api/v1/adapters", response_model=list[Capability], tags=["operations"])
def adapters() -> list[Capability]:
    return [
        Capability(id=name, name=name.replace("_", " ").title()) for name in service.adapters.names
    ]


@app.get("/api/v1/templates/csv", response_class=PlainTextResponse, tags=["ingestion"])
def csv_template() -> PlainTextResponse:
    content = (
        "timestamp,source,category,event_type,host,service,message,disk_used_percent,mount\n"
        "2026-10-02T09:00:00Z,node-exporter,system,disk_usage,web-01,,Root filesystem usage high,96.4,/\n"
    )
    return PlainTextResponse(
        content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=cyberguard-telemetry-template.csv"},
    )


@app.get("/api/v1/datasets", response_model=list[DatasetResponse], tags=["datasets"])
def datasets() -> list[dict]:
    return list_datasets()


@app.get("/api/v1/plugins", response_model=list[PluginInfo], tags=["plugins"])
def plugins() -> list[PluginInfo]:
    return service.plugins


@app.get("/api/v1/plugin-api-version", tags=["plugins"])
def plugin_api_version() -> dict[str, str]:
    return {"version": PLUGIN_API_VERSION}


@app.get("/api/v1/agents", response_model=list[AgentStatus], tags=["agents"])
def list_agents() -> list[AgentStatus]:
    return service.store.list_agents(settings.agent_stale_seconds)


@app.post("/api/v1/agents/heartbeat", response_model=IngestResponse, tags=["agents"])
async def agent_heartbeat(
    heartbeat: AgentHeartbeat, request: Request, authorization: str | None = Header(None)
) -> IngestResponse:
    if settings.agent_token:
        expected = f"Bearer {settings.agent_token}"
        if not authorization or not secrets.compare_digest(authorization, expected):
            raise HTTPException(401, "Invalid agent token")
    started = time.perf_counter()
    incidents = await run_in_threadpool(service.ingest_events, heartbeat.events)
    await run_in_threadpool(service.store.save_agent_heartbeat, heartbeat, len(incidents))
    return IngestResponse(
        accepted_events=len(heartbeat.events),
        incidents=incidents,
        diagnosis=diagnose(heartbeat.events, incidents),
        processing_ms=round((time.perf_counter() - started) * 1000, 2),
        request_id=request.state.request_id,
    )


@app.post("/api/v1/demo/load", response_model=IngestResponse, tags=["demo"])
async def load_complete_demo(request: Request) -> IngestResponse:
    started = time.perf_counter()
    events = complete_demo_events()
    incidents = await run_in_threadpool(service.ingest_events, events)
    return IngestResponse(
        accepted_events=len(events),
        incidents=incidents,
        diagnosis=diagnose(events, incidents),
        processing_ms=round((time.perf_counter() - started) * 1000, 2),
        request_id=request.state.request_id,
    )


@app.post("/api/v1/ingest/events", response_model=IngestResponse, tags=["ingestion"])
async def ingest_events(
    batch: EventBatch, request: Request, persist: bool = True
) -> IngestResponse:
    started = time.perf_counter()
    operation = service.ingest_events if persist else service.analyze_events
    incidents = await run_in_threadpool(operation, batch.events)
    return IngestResponse(
        accepted_events=len(batch.events),
        incidents=incidents,
        diagnosis=diagnose(batch.events, incidents),
        processing_ms=round((time.perf_counter() - started) * 1000, 2),
        request_id=request.state.request_id,
    )


@app.post("/api/v1/ingest/file", response_model=IngestResponse, tags=["ingestion"])
async def ingest_file(
    request: Request, file: UploadFile = File(...), adapter: str | None = Form(None)
) -> IngestResponse:
    started = time.perf_counter()
    content = await file.read(settings.max_upload_bytes + 1)
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(
            413, f"File exceeds the {settings.max_upload_bytes // 1_048_576} MB upload limit"
        )
    original_name = Path(file.filename or "upload").name
    suffix = "".join(Path(original_name).suffixes) or (
        original_name if original_name.startswith(".") else ""
    )
    safe_stem = "".join(
        character
        for character in Path(original_name).stem
        if character.isalnum() or character in "-_"
    )[:60]
    with NamedTemporaryFile(prefix=f"{safe_stem or 'upload'}-", suffix=suffix, delete=False) as tmp:
        tmp.write(content)
        path = Path(tmp.name)
    try:
        selected_adapter = (
            service.adapters.get(adapter) if adapter else service.adapters.detect(path)
        )
        events = await run_in_threadpool(selected_adapter.parse, path)
        incidents = await run_in_threadpool(service.ingest_events, events)
        manifest = build_manifest(
            original_name, selected_adapter.name, events, len(service.rules.rule_ids)
        )
    except (UnicodeError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc
    finally:
        path.unlink(missing_ok=True)
    return IngestResponse(
        accepted_events=len(events),
        incidents=incidents,
        diagnosis=diagnose(events, incidents),
        manifest=manifest,
        processing_ms=round((time.perf_counter() - started) * 1000, 2),
        request_id=request.state.request_id,
    )


@app.get("/api/v1/incidents", response_model=list[Incident], tags=["incidents"])
def get_incidents(
    limit: int = 100,
    offset: int = 0,
    severity: Severity | None = None,
    status: IncidentStatus | None = None,
) -> list[Incident]:
    return service.store.list_incidents(min(max(limit, 1), 500), max(offset, 0), severity, status)


@app.get("/api/v1/incidents/{incident_id}", response_model=Incident, tags=["incidents"])
def get_incident(incident_id: str) -> Incident:
    incident = service.store.get_incident(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident


@app.patch("/api/v1/incidents/{incident_id}/status", response_model=Incident, tags=["incidents"])
def update_incident_status(incident_id: str, update: StatusUpdate) -> Incident:
    incident = service.store.update_incident_status(incident_id, update.status)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident
