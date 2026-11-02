from collections import defaultdict

from cyberguard.core.enums import EventCategory, Severity
from cyberguard.core.models import Evidence, Finding, TelemetryEvent
from cyberguard.detection.base import DetectionRule


class DatabasePoolRule(DetectionRule):
    rule_id = "CG-APP-002"
    title = "Database connection-pool failure"
    TOKENS = ("connection pool exhausted", "timeout acquiring connection", "pool timeout", "too many connections")

    def __init__(self, threshold: int = 3) -> None:
        self.threshold = threshold

    def evaluate(self, events: list[TelemetryEvent]) -> list[Finding]:
        groups = defaultdict(list)
        for e in events:
            if e.category == EventCategory.APPLICATION and any(token in e.message.lower() for token in self.TOKENS):
                groups[(e.host or "unknown", e.service or "application")].append(e)
        results = []
        for (host, service), failures in groups.items():
            if len(failures) >= self.threshold:
                results.append(Finding(rule_id=self.rule_id, title=self.title, category=EventCategory.APPLICATION,
                    severity=Severity.HIGH, confidence=0.92,
                    summary=f"{len(failures)} database pool failures detected for {service} on {host}.",
                    root_cause="The application cannot obtain database connections due to saturation, leaks, slow queries, or database unavailability.",
                    evidence=[Evidence(event_id=e.id, summary=e.message) for e in failures[:20]],
                    analyst_checks=["Check database reachability, active sessions, slow queries, and pool metrics.", "Compare pool demand with recent traffic and deployments."],
                    remediation=["Fix confirmed connection leaks or query latency before increasing pool limits.", "Restore database availability through the approved runbook."],
                    validation=["Run a representative transaction and confirm pool waiters/timeouts remain at baseline."],
                    limitations=["Message matching depends on application log wording."],
                    correlation_key=f"dbpool:{host}:{service}"))
        return results
