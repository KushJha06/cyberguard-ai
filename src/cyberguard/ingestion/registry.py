from pathlib import Path

from .base import Adapter


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, Adapter] = {}

    def register(self, adapter: Adapter) -> None:
        self._adapters[adapter.name] = adapter

    def get(self, name: str) -> Adapter:
        if name not in self._adapters:
            raise ValueError(f"Unknown adapter: {name}")
        return self._adapters[name]

    def detect(self, path: Path) -> Adapter:
        matches = [adapter for adapter in self._adapters.values() if adapter.supports(path)]
        if len(matches) == 1:
            return matches[0]
        if not matches and "universal_text" in self._adapters:
            return self._adapters["universal_text"]
        raise ValueError("The file extension is ambiguous; choose an adapter explicitly")

    @property
    def names(self) -> list[str]:
        return sorted(self._adapters)
