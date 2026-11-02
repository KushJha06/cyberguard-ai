import re
import shutil
from collections import Counter
from pathlib import Path

from pydantic import BaseModel, Field

from cyberguard.config import get_settings
from cyberguard.core.models import Incident, TelemetryEvent


class DiagnosticSummary(BaseModel):
    primary_issue_area: str
    input_classification: str
    readiness: str
    summary: str
    event_categories: dict[str, int] = Field(default_factory=dict)
    likely_causes: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    indicators: dict[str, int] = Field(default_factory=dict)
    sample_evidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class PreflightCheck(BaseModel):
    name: str
    status: str
    detail: str
    action: str | None = None


class PreflightReport(BaseModel):
    ready: bool
    checks: list[PreflightCheck]


_AREA_LABELS = {
    "application": "application",
    "system": "system_or_infrastructure",
    "configuration": "system_configuration",
    "authentication": "security_or_authentication_logs",
    "file_integrity": "file_integrity",
    "network": "network_telemetry",
    "unknown": "logs_or_telemetry",
}


def diagnose(events: list[TelemetryEvent], incidents: list[Incident]) -> DiagnosticSummary:
    event_counts = Counter(event.category.value for event in events)
    incident_counts = Counter(incident.category.value for incident in incidents)
    indicator_pattern = re.compile(r"\b(fatal|panic|exceptions?|traceback|errors?|failed|failure|permission denied|connection refused|timed?\s*out)\b", re.I)
    indicator_counts: Counter[str] = Counter()
    samples = []
    for event in events:
        matches = [match.lower() for match in indicator_pattern.findall(event.message)]
        level = str(event.attributes.get("log_level", "")).lower()
        if level in {"error", "err", "fatal", "critical", "crit", "failed", "failure"}:
            matches.append(level)
        indicator_counts.update(matches)
        if matches and len(samples) < 10:
            location = event.attributes.get("archive_member") or event.attributes.get("filename") or event.source
            line = event.attributes.get("line_number") or event.attributes.get("csv_row")
            samples.append(f"{location}{f':{line}' if line else ''} — {event.message[:240]}")
    if incident_counts:
        primary_category = incident_counts.most_common(1)[0][0]
        primary_area = _AREA_LABELS.get(primary_category, "logs_or_telemetry")
        causes = list(dict.fromkeys(incident.root_cause for incident in incidents))[:5]
        actions = list(dict.fromkeys(action for incident in incidents for action in incident.analyst_checks))[:4]
        actions += [action for action in dict.fromkeys(
            action for incident in incidents for action in incident.remediation) if action not in actions][:4]
        limitations = list(dict.fromkeys(item for incident in incidents for item in incident.limitations))[:4]
        summary = (f"CyberGuard found {len(incidents)} actionable issue(s). The strongest concentration is in "
            f"{primary_area.replace('_', ' ')}; use the evidence and validation steps before remediation.")
        readiness = "blocked" if any(item.severity.value in {"critical", "high"} for item in incidents) else "review"
    else:
        primary_category = event_counts.most_common(1)[0][0] if event_counts else "unknown"
        primary_area = _AREA_LABELS.get(primary_category, "logs_or_telemetry")
        if indicator_counts:
            readiness = "review"
            summary = (f"The input contains {sum(indicator_counts.values())} failure indicator(s), but no "
                "specialized rule produced an incident. Review the sampled records and source manifest.")
            causes = ["Observed indicators: " + ", ".join(
                f"{name} ({count})" for name, count in indicator_counts.most_common())]
            actions = ["Review surrounding lines, timestamps, host/service context and recent changes.",
                "Confirm dependencies, permissions, available capacity and configuration validity."]
        else:
            readiness = "ready"
            summary = "No currently implemented detection matched this input. This does not guarantee the system is error-free."
            causes = []
            actions = ["Confirm the file covers the intended host, service and time window before proceeding."]
        limitations = ["Generic files may lack structured fields needed for confident root-cause analysis."]
    input_classification = ", ".join(f"{key}: {value}" for key, value in event_counts.items()) or "unknown"
    return DiagnosticSummary(primary_issue_area=primary_area, input_classification=input_classification,
        readiness=readiness, summary=summary, event_categories=dict(event_counts), likely_causes=causes,
        recommended_actions=actions[:8], indicators=dict(indicator_counts), sample_evidence=samples,
        limitations=limitations)


def run_preflight() -> PreflightReport:
    settings = get_settings()
    checks: list[PreflightCheck] = []
    db_parent = Path(settings.database_path).parent
    upload_dir = Path(settings.upload_dir)
    for path, name in ((db_parent, "Database directory"), (upload_dir, "Upload directory")):
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".cyberguard-write-test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            checks.append(PreflightCheck(name=name, status="pass", detail=f"Writable: {path}"))
        except OSError as exc:
            checks.append(PreflightCheck(name=name, status="fail", detail=str(exc),
                action=f"Grant the CyberGuard process write access to {path}"))
    free = shutil.disk_usage(db_parent).free
    if free < 512 * 1024 * 1024:
        checks.append(PreflightCheck(name="Free disk space", status="warn",
            detail=f"Only {free / 1024**2:.0f} MB available",
            action="Free disk space before ingesting telemetry."))
    else:
        checks.append(PreflightCheck(name="Free disk space", status="pass",
            detail=f"{free / 1024**3:.1f} GB available"))
    checks.append(PreflightCheck(name="Upload policy", status="pass",
        detail=f"Maximum {settings.max_upload_bytes / 1024**2:.0f} MB and {settings.max_batch_events:,} events per request"))
    return PreflightReport(ready=not any(check.status == "fail" for check in checks), checks=checks)
