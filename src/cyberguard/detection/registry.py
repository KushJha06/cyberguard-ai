from cyberguard.core.models import Finding, TelemetryEvent

from .base import DetectionRule


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, DetectionRule] = {}

    def register(self, rule: DetectionRule) -> None:
        self._rules[rule.rule_id] = rule

    def run(self, events: list[TelemetryEvent]) -> list[Finding]:
        return [finding for rule in self._rules.values() for finding in rule.evaluate(events)]

    @property
    def rule_ids(self) -> list[str]:
        return sorted(self._rules)

    @property
    def capabilities(self) -> list[tuple[str, str]]:
        return [(rule_id, self._rules[rule_id].title) for rule_id in self.rule_ids]
