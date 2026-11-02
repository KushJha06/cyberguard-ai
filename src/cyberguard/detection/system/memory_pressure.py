from cyberguard.core.enums import EventCategory, Severity
from cyberguard.core.models import Evidence, Finding, TelemetryEvent
from cyberguard.detection.base import DetectionRule


class MemoryPressureRule(DetectionRule):
    rule_id = "CG-SYS-002"
    title = "Sustained memory pressure"

    def __init__(self, threshold_percent: float = 92) -> None:
        self.threshold = threshold_percent

    def evaluate(self, events: list[TelemetryEvent]) -> list[Finding]:
        findings = []
        for event in events:
            value = event.attributes.get("memory_used_percent")
            try: value = float(value)
            except (TypeError, ValueError): continue
            if value < self.threshold: continue
            host = event.host or "unknown"
            findings.append(Finding(rule_id=self.rule_id, title=self.title, category=EventCategory.SYSTEM,
                severity=Severity.CRITICAL if value >= 98 else Severity.HIGH, confidence=.95,
                summary=f"Memory utilization is {value:.1f}% on {host}.",
                root_cause="Available memory is nearly exhausted, increasing paging and process-termination risk.",
                evidence=[Evidence(event_id=event.id, summary=event.message, details={"used_percent": value})],
                analyst_checks=["Inspect top consumers, swap activity, OOM events, and recent workload changes."],
                remediation=["Correct a confirmed leak or scale capacity through approved change control."],
                validation=["Confirm memory, swap, and latency remain at baseline under representative load."],
                limitations=["A point-in-time utilization value does not prove a memory leak."],
                correlation_key=f"memory:{host}"))
        return findings
