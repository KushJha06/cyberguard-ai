import json
from pathlib import Path

from cyberguard.config import get_settings
from cyberguard.core.models import TelemetryEvent

from .base import Adapter


class JSONAdapter(Adapter):
    name = "json"
    extensions = (".json", ".jsonl")

    def parse(self, path: Path) -> list[TelemetryEvent]:
        limit = get_settings().max_batch_events
        if path.suffix.lower() == ".jsonl":
            events = []
            with path.open(encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, 1):
                    if not line.strip():
                        continue
                    if len(events) >= limit:
                        raise ValueError(f"File exceeds the {limit:,}-event limit")
                    try:
                        events.append(TelemetryEvent.model_validate(json.loads(line)))
                    except (json.JSONDecodeError, ValueError) as exc:
                        raise ValueError(f"Invalid JSONL record at line {line_number}: {exc}") from exc
            return events
        payload = json.loads(path.read_text(encoding="utf-8"))
        records = payload if isinstance(payload, list) else payload.get("events", [payload])
        if len(records) > limit:
            raise ValueError(f"File exceeds the {limit:,}-event limit")
        return [TelemetryEvent.model_validate(record) for record in records]
