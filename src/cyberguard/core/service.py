from pathlib import Path

from cyberguard.config import get_settings
from cyberguard.detection import default_registry as default_rules
from cyberguard.ingestion import default_registry as default_adapters
from cyberguard.plugins import built_in_plugins, load_external_plugins
from cyberguard.storage.sqlite import SQLiteStore

from .correlation import group_findings
from .incident_manager import incident_from_findings
from .models import Incident, TelemetryEvent
from .redaction import redact


class TriageService:
    def __init__(self, store: SQLiteStore | None = None) -> None:
        settings = get_settings()
        self.store = store or SQLiteStore(settings.database_path, settings.sqlite_busy_timeout_ms)
        self.max_batch_events = settings.max_batch_events
        self.adapters = default_adapters()
        self.rules = default_rules()
        built_ins = built_in_plugins(self.adapters, self.rules)
        external = load_external_plugins(self.adapters, self.rules, settings.enable_external_plugins)
        self.plugins = built_ins + external
        self.redact_sensitive = settings.redact_sensitive

    def ingest_events(self, events: list[TelemetryEvent]) -> list[Incident]:
        if len(events) > self.max_batch_events:
            raise ValueError(f"Batch exceeds the {self.max_batch_events:,}-event limit")
        if self.redact_sensitive:
            events = [TelemetryEvent.model_validate(redact(event.model_dump())) for event in events]
        self.store.save_events(events)
        findings = self.rules.run(events)
        incidents = [incident_from_findings(group) for group in group_findings(findings).values()]
        for incident in incidents:
            existing = self.store.get_incident_by_correlation(incident.correlation_key)
            if existing:
                incident.id = existing.id
                incident.created_at = existing.created_at
                incident.status = existing.status
        self.store.save_incidents(incidents)
        return incidents

    def analyze_events(self, events: list[TelemetryEvent]) -> list[Incident]:
        """Run detections without persisting input; useful for evaluation and dry runs."""
        if len(events) > self.max_batch_events:
            raise ValueError(f"Batch exceeds the {self.max_batch_events:,}-event limit")
        findings = self.rules.run(events)
        return [incident_from_findings(group) for group in group_findings(findings).values()]

    def ingest_file(self, path: Path, adapter_name: str | None = None) -> tuple[list[TelemetryEvent], list[Incident]]:
        adapter = self.adapters.get(adapter_name) if adapter_name else self.adapters.detect(path)
        events = adapter.parse(path)
        return events, self.ingest_events(events)
