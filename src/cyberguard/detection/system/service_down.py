from cyberguard.core.enums import EventCategory, Severity
from cyberguard.core.models import Evidence, Finding, TelemetryEvent
from cyberguard.detection.base import DetectionRule


class ServiceDownRule(DetectionRule):
    rule_id = "CG-SYS-003"
    title = "Service unavailable"

    def evaluate(self, events: list[TelemetryEvent]) -> list[Finding]:
        findings = []
        for event in events:
            state = str(event.attributes.get("service_state", "")).lower()
            if event.event_type != "service_status" or state not in {"down", "failed", "inactive"}:
                continue
            host, service = event.host or "unknown", event.service or "unknown"
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    category=EventCategory.SYSTEM,
                    severity=Severity.HIGH,
                    confidence=0.97,
                    summary=f"{service} is {state} on {host}.",
                    root_cause="The monitored service is not in a healthy running state.",
                    evidence=[
                        Evidence(event_id=event.id, summary=event.message, details={"state": state})
                    ],
                    analyst_checks=[
                        "Review service logs, dependency health, exit code, and recent changes."
                    ],
                    remediation=[
                        "Address the confirmed cause before restarting through the approved runbook."
                    ],
                    validation=["Confirm health checks and a representative transaction succeed."],
                    limitations=["A monitoring failure can resemble service unavailability."],
                    correlation_key=f"service:{host}:{service}",
                )
            )
        return findings
