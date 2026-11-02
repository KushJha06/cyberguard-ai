from collections import Counter
from pathlib import Path

from pydantic import BaseModel, Field

from cyberguard.core.models import TelemetryEvent


class AnalysisManifest(BaseModel):
    uploaded_file: str
    adapter: str
    files_analyzed: list[str] = Field(default_factory=list)
    events_evaluated: int
    rules_evaluated: int
    event_categories: dict[str, int] = Field(default_factory=dict)
    event_types: dict[str, int] = Field(default_factory=dict)
    sources: dict[str, int] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)


def build_manifest(filename: str, adapter: str, events: list[TelemetryEvent], rule_count: int) -> AnalysisManifest:
    members = {str(event.attributes["archive_member"]) for event in events
        if event.attributes.get("archive_member")}
    files = members or {Path(filename).name}
    notes = []
    unknown = sum(event.category.value == "unknown" for event in events)
    if unknown:
        notes.append(f"{unknown} event(s) could not be assigned a specific category.")
    if adapter == "universal_text":
        notes.append("Universal text inspection was used; structured fields may be unavailable.")
    if adapter == "archive":
        notes.append("Only safe, supported archive members that produced events are listed.")
    return AnalysisManifest(uploaded_file=Path(filename).name, adapter=adapter,
        files_analyzed=sorted(files), events_evaluated=len(events), rules_evaluated=rule_count,
        event_categories=dict(Counter(event.category.value for event in events)),
        event_types=dict(Counter(event.event_type for event in events)),
        sources=dict(Counter(event.source for event in events)), notes=notes)
