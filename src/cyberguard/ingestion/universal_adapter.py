import csv
import io
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from cyberguard.config import get_settings
from cyberguard.core.enums import EventCategory
from cyberguard.core.models import TelemetryEvent

from .base import Adapter
from .config_file_adapter import SSHConfigAdapter
from .csv_adapter import CSVAdapter
from .json_adapter import JSONAdapter

_BINARY_BYTES = set(range(0, 9)) | {11, 12} | set(range(14, 32))
_TIMESTAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ][0-9:.+-]+Z?)\s*")


class UniversalTextAdapter(Adapter):
    """Safely inspect unknown text files and normalize each useful line."""

    name = "universal_text"
    extensions: tuple[str, ...] = ()

    def supports(self, path: Path) -> bool:
        return False

    def parse(self, path: Path) -> list[TelemetryEvent]:
        data = path.read_bytes()
        if not data:
            raise ValueError("The uploaded file is empty")
        sample = data[:8192]
        if b"\x00" in sample or sum(byte in _BINARY_BYTES for byte in sample) / len(sample) > 0.05:
            raise ValueError(
                "This appears to be a binary file. CyberGuard safely accepts text-based logs, JSON, "
                "JSONL, CSV and configuration files; export binary data to one of those formats first."
            )
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            try:
                text = data.decode("latin-1")
            except UnicodeDecodeError as exc:
                raise ValueError("The file is not readable text; export it as UTF-8") from exc

        stripped = text.lstrip()
        if stripped.startswith(("{", "[")):
            return self._parse_json_content(path, text)
        if self._looks_like_csv(text):
            return self._parse_csv_content(path, text)
        if self._looks_like_ssh_config(text):
            return SSHConfigAdapter().parse(path)
        return self._parse_lines(path, text)

    def _parse_json_content(self, path: Path, text: str) -> list[TelemetryEvent]:
        try:
            json.loads(text)
            suffix = ".json"
        except json.JSONDecodeError:
            suffix = ".jsonl"
        temporary = path.with_suffix(suffix)
        temporary.write_text(text, encoding="utf-8")
        try:
            return JSONAdapter().parse(temporary)
        finally:
            if temporary != path:
                temporary.unlink(missing_ok=True)

    def _parse_csv_content(self, path: Path, text: str) -> list[TelemetryEvent]:
        temporary = path.with_suffix(".csv")
        temporary.write_text(text, encoding="utf-8")
        try:
            return CSVAdapter().parse(temporary)
        finally:
            if temporary != path:
                temporary.unlink(missing_ok=True)

    @staticmethod
    def _looks_like_csv(text: str) -> bool:
        first_lines = [line for line in text.splitlines()[:5] if line.strip()]
        if len(first_lines) < 2:
            return False
        try:
            dialect = csv.Sniffer().sniff("\n".join(first_lines), delimiters=",;\t|")
            rows = list(csv.reader(io.StringIO("\n".join(first_lines)), dialect))
            return len(rows[0]) > 1 and all(len(row) == len(rows[0]) for row in rows[1:])
        except csv.Error:
            return False

    @staticmethod
    def _looks_like_ssh_config(text: str) -> bool:
        directives = ("permitrootlogin", "passwordauthentication", "permitemptypasswords", "protocol ")
        lowered = text.lower()
        return any(re.search(rf"(?m)^\s*{directive}", lowered) for directive in directives)

    def _parse_lines(self, path: Path, text: str) -> list[TelemetryEvent]:
        limit = get_settings().max_batch_events
        events = []
        for line_number, line in enumerate(text.splitlines(), 1):
            message = line.strip()
            if not message:
                continue
            if len(events) >= limit:
                raise ValueError(f"File exceeds the {limit:,}-event limit")
            timestamp = datetime.now(UTC)
            match = _TIMESTAMP.match(message)
            if match:
                try:
                    timestamp = datetime.fromisoformat(match.group(1).replace("Z", "+00:00"))
                except ValueError:
                    pass
            category, event_type = self._classify_line(message)
            events.append(TelemetryEvent(timestamp=timestamp, source=f"file:{path.name}", category=category,
                event_type=event_type, message=message,
                attributes={"line_number": line_number, "filename": path.name}))
        if not events:
            raise ValueError("The file contains no non-empty text records")
        return events

    @staticmethod
    def _classify_line(message: str) -> tuple[EventCategory, str]:
        text = message.lower()
        if any(token in text for token in ("failed password", "authentication failure", "login failed")):
            return EventCategory.AUTHENTICATION, "authentication_log"
        if any(token in text for token in ("http/1.", "status=", "exception", "traceback", "stack trace")):
            return EventCategory.APPLICATION, "application_log"
        if any(token in text for token in ("systemd", "kernel", "filesystem", "out of memory", "disk full")):
            return EventCategory.SYSTEM, "system_log"
        if any(token in text for token in ("server {", "services:", "listen ", "permitrootlogin")):
            return EventCategory.CONFIGURATION, "configuration_text"
        return EventCategory.UNKNOWN, "log_line"
