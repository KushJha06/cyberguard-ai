from abc import ABC, abstractmethod
from pathlib import Path

from cyberguard.core.models import TelemetryEvent


class Adapter(ABC):
    name: str
    extensions: tuple[str, ...] = ()

    @abstractmethod
    def parse(self, path: Path) -> list[TelemetryEvent]: ...

    def supports(self, path: Path) -> bool:
        return path.suffix.lower() in self.extensions
