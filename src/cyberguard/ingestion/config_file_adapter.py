import re
from pathlib import Path

from cyberguard.core.enums import EventCategory
from cyberguard.core.models import TelemetryEvent

from .base import Adapter


class SSHConfigAdapter(Adapter):
    name = "ssh_config"
    extensions = (".conf", ".config")

    def supports(self, path: Path) -> bool:
        name = path.name.lower()
        return super().supports(path) and any(token in name for token in ("ssh", "sshd"))

    def parse(self, path: Path) -> list[TelemetryEvent]:
        directives: dict[str, str] = {}
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = re.split(r"\s+", line, maxsplit=1)
            if len(parts) == 2:
                directives[parts[0].lower()] = parts[1].strip()
        return [TelemetryEvent(source="ssh_config", category=EventCategory.CONFIGURATION,
            event_type="ssh_config_snapshot", host=path.name, message=f"Parsed SSH configuration {path.name}",
            attributes={"directives": directives})]
