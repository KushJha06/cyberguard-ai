from cyberguard.core.enums import EventCategory, Severity
from cyberguard.core.models import Evidence, Finding, TelemetryEvent
from cyberguard.detection.base import DetectionRule


class CapacityForecastRule(DetectionRule):
    rule_id = "CG-SYS-004"
    title = "Projected disk-capacity exhaustion"

    def __init__(self, warning_minutes: float = 240) -> None:
        self.warning_minutes = warning_minutes

    def evaluate(self, events: list[TelemetryEvent]) -> list[Finding]:
        findings = []
        for event in events:
            projected = event.attributes.get("projected_minutes_to_full")
            used = event.attributes.get("disk_used_percent")
            try:
                projected, used = float(projected), float(used)
            except (TypeError, ValueError):
                continue
            if projected > self.warning_minutes or used >= 90:
                continue
            mount, host = str(event.attributes.get("mount", "/")), event.host or "unknown"
            findings.append(Finding(rule_id=self.rule_id, title=self.title,
                category=EventCategory.SYSTEM,
                severity=Severity.HIGH if projected <= 60 else Severity.MEDIUM, confidence=.78,
                summary=f"At the observed growth rate, {host}:{mount} may fill in approximately {projected:.0f} minutes.",
                root_cause="Recent filesystem growth projects capacity exhaustion before the current static threshold is reached.",
                evidence=[Evidence(event_id=event.id, summary=event.message,
                    details={"used_percent": used, "projected_minutes_to_full": projected,
                        "growth_percent_per_hour": event.attributes.get("growth_percent_per_hour")})],
                analyst_checks=["Confirm growth persists across multiple samples and identify the fastest-growing paths."],
                remediation=["Correct retention or growth at the source, or schedule approved capacity expansion before exhaustion."],
                validation=["Confirm the projected time-to-full recovers and utilization remains within the capacity budget."],
                limitations=["Forecasts based on two recent samples are sensitive to short-lived bursts."],
                correlation_key=f"disk-forecast:{host}:{mount}"))
        return findings
