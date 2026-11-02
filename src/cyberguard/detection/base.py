from abc import ABC, abstractmethod

from cyberguard.core.models import Finding, TelemetryEvent


class DetectionRule(ABC):
    rule_id: str
    title: str

    @abstractmethod
    def evaluate(self, events: list[TelemetryEvent]) -> list[Finding]: ...
