import csv
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cyberguard.config import get_settings
from cyberguard.core.enums import EventCategory
from cyberguard.core.models import TelemetryEvent

from .base import Adapter

_FIELD_ALIASES = {
    "timestamp": ("timestamp", "time", "datetime", "date_time", "event_time", "@timestamp"),
    "source": ("source", "source_name", "sensor", "observer", "log_source"),
    "category": ("category", "event_category", "type_category"),
    "event_type": ("event_type", "event", "type", "event_name", "event_id", "eventid"),
    "host": ("host", "hostname", "computer", "device", "node"),
    "service": ("service", "application", "app", "component", "process"),
    "message": (
        "message",
        "msg",
        "log",
        "description",
        "detail",
        "error",
        "label",
        "content",
        "event_template",
        "eventtemplate",
    ),
}
_ATTRIBUTE_ALIASES = {
    "status_code": ("status_code", "status", "http_status", "response_code"),
    "disk_used_percent": ("disk_used_percent", "disk_usage", "disk_percent", "filesystem_usage"),
    "memory_used_percent": ("memory_used_percent", "memory_usage", "memory_percent", "mem_usage"),
    "source_ip": ("source_ip", "src_ip", "srcip", "client_ip", "ip_address"),
    "outcome": ("outcome", "result", "login_result", "auth_result"),
    "service_state": ("service_state", "state", "status_text"),
    "mount": ("mount", "mountpoint", "filesystem"),
    "path": ("path", "file_path", "filename"),
    "action": ("action", "operation", "change_type"),
    "command_line": ("command_line", "commandline", "cmdline", "command"),
    "log_level": ("log_level", "level", "severity", "priority"),
    "error_code": ("error_code", "errno", "exit_code", "return_code"),
}


class CSVAdapter(Adapter):
    """Flexible CSV normalizer supporting canonical and common third-party columns."""

    name = "csv"
    extensions = (".csv",)

    def parse(self, path: Path) -> list[TelemetryEvent]:
        limit = get_settings().max_batch_events
        events: list[TelemetryEvent] = []
        with path.open(encoding="utf-8-sig", newline="", errors="replace") as handle:
            sample = handle.read(8192)
            if not sample.strip():
                raise ValueError("The CSV file is empty")
            handle.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            except csv.Error:
                dialect = csv.excel
            reader = csv.DictReader(handle, dialect=dialect)
            if not reader.fieldnames:
                raise ValueError("The CSV file has no header row")
            for index, row in enumerate(reader, 1):
                if index > limit:
                    raise ValueError(f"File exceeds the {limit:,}-event limit")
                if not any(value and str(value).strip() for value in row.values()):
                    continue
                events.append(self._event(row, path.name, index))
        if not events:
            raise ValueError("The CSV file contains no data rows")
        return events

    def _event(
        self, row: dict[str, str], filename: str = "upload.csv", row_number: int = 0
    ) -> TelemetryEvent:
        normalized = {
            self._key(key): value.strip() if isinstance(value, str) else value
            for key, value in row.items()
            if key is not None
        }
        timestamp_value = self._value(normalized, "timestamp")
        if normalized.get("date") and normalized.get("time") and not normalized.get("timestamp"):
            timestamp_value = f"{normalized['date']} {normalized['time']}"
        timestamp = self._timestamp(timestamp_value)
        source = (
            self._value(normalized, "source") or normalized.get("component") or f"csv:{filename}"
        )
        host = self._value(normalized, "host") or None
        service = self._value(normalized, "service") or None
        message = self._value(normalized, "message") or self._fallback_message(
            normalized, row_number
        )
        attributes = self._attributes(normalized)
        known_aliases = {alias for aliases in _FIELD_ALIASES.values() for alias in aliases}
        attribute_aliases = {alias for aliases in _ATTRIBUTE_ALIASES.values() for alias in aliases}
        for key, value in normalized.items():
            if key not in known_aliases | attribute_aliases and value not in (None, ""):
                attributes[key] = self._coerce(value)
        category = self._category(self._value(normalized, "category"), message, attributes)
        if category == EventCategory.UNKNOWN:
            lowered_filename = filename.lower()
            if any(
                token in lowered_filename for token in ("apache", "nginx", "application", "app_")
            ):
                category = EventCategory.APPLICATION
            elif any(token in lowered_filename for token in ("openssh", "sshd", "auth")):
                category = EventCategory.AUTHENTICATION
            elif any(token in lowered_filename for token in ("linux", "bgl", "hdfs", "system")):
                category = EventCategory.SYSTEM
        event_type = self._value(normalized, "event_type") or self._event_type(
            category, message, attributes
        )
        attributes.setdefault("csv_row", row_number)
        return TelemetryEvent(
            timestamp=timestamp,
            source=str(source),
            category=category,
            event_type=str(event_type),
            host=str(host) if host else None,
            service=str(service) if service else None,
            message=str(message),
            attributes=attributes,
            raw=row,
        )

    @staticmethod
    def _key(value: str) -> str:
        return value.strip().lower().replace(" ", "_").replace("-", "_")

    @staticmethod
    def _value(row: dict[str, Any], field: str) -> Any:
        return next(
            (row.get(alias) for alias in _FIELD_ALIASES[field] if row.get(alias) not in (None, "")),
            None,
        )

    def _attributes(self, row: dict[str, Any]) -> dict[str, Any]:
        attributes = {}
        for canonical, aliases in _ATTRIBUTE_ALIASES.items():
            value = next(
                (row.get(alias) for alias in aliases if row.get(alias) not in (None, "")), None
            )
            if value is not None:
                coerced = self._coerce(value)
                if canonical in {"outcome", "service_state", "action", "log_level"} and isinstance(
                    coerced, str
                ):
                    coerced = coerced.lower()
                attributes[canonical] = coerced
        return attributes

    @staticmethod
    def _timestamp(value: Any) -> datetime:
        if not value:
            return datetime.now(UTC)
        text = str(value).strip()
        if text.isdigit():
            number = int(text)
            if number > 10_000_000_000:
                number //= 1000
            try:
                return datetime.fromtimestamp(number, UTC)
            except (ValueError, OSError):
                return datetime.now(UTC)
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            return parsed.replace(tzinfo=parsed.tzinfo or UTC)
        except ValueError:
            for pattern in ("%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S"):
                try:
                    return datetime.strptime(text, pattern).replace(tzinfo=UTC)
                except ValueError:
                    continue
        return datetime.now(UTC)

    @staticmethod
    def _category(explicit: Any, message: str, attributes: dict[str, Any]) -> EventCategory:
        if explicit:
            value = str(explicit).lower().replace(" ", "_")
            try:
                return EventCategory(value)
            except ValueError:
                pass
        text = message.lower()
        if "source_ip" in attributes or any(
            token in text for token in ("login", "password", "authentication")
        ):
            return EventCategory.AUTHENTICATION
        if (
            "disk_used_percent" in attributes
            or "memory_used_percent" in attributes
            or "service_state" in attributes
        ):
            return EventCategory.SYSTEM
        if "status_code" in attributes or any(
            token in text for token in ("exception", "traceback", "http")
        ):
            return EventCategory.APPLICATION
        if "path" in attributes and "action" in attributes:
            return EventCategory.FILE_INTEGRITY
        if any(key in attributes for key in ("src_port", "dst_port", "protocol", "destination_ip")):
            return EventCategory.NETWORK
        return EventCategory.UNKNOWN

    @staticmethod
    def _event_type(category: EventCategory, message: str, attributes: dict[str, Any]) -> str:
        if "disk_used_percent" in attributes:
            return "disk_usage"
        if "memory_used_percent" in attributes:
            return "memory_usage"
        if "service_state" in attributes:
            return "service_status"
        if "status_code" in attributes:
            return "http_request"
        if "path" in attributes and "action" in attributes:
            return "file_change"
        if "command_line" in attributes:
            return "process_start"
        if category == EventCategory.AUTHENTICATION:
            return "login"
        if category == EventCategory.NETWORK:
            return "network_flow"
        return "log_record"

    @staticmethod
    def _fallback_message(row: dict[str, Any], row_number: int) -> str:
        values = [
            f"{key}={value}" for key, value in list(row.items())[:6] if value not in (None, "")
        ]
        return "; ".join(values) or f"CSV record {row_number}"

    @staticmethod
    def _coerce(value: Any) -> Any:
        if not isinstance(value, str):
            return value
        stripped = value.strip()
        for cast in (int, float):
            try:
                return cast(stripped)
            except ValueError:
                pass
        if stripped.lower() in {"true", "false"}:
            return stripped.lower() == "true"
        return stripped
