from collections import defaultdict

from cyberguard.core.enums import EventCategory, Severity
from cyberguard.core.models import Evidence, Finding, TelemetryEvent
from cyberguard.detection.base import DetectionRule


class HTTPErrorSpikeRule(DetectionRule):
    rule_id = "CG-APP-001"
    title = "HTTP 5xx error spike"

    def __init__(self, minimum_errors: int = 5, error_rate: float = 0.2) -> None:
        self.minimum_errors, self.error_rate = minimum_errors, error_rate

    def evaluate(self, events: list[TelemetryEvent]) -> list[Finding]:
        groups = defaultdict(list)
        for e in events:
            if e.category == EventCategory.APPLICATION and (
                "status_code" in e.attributes or e.event_type == "http_request"
            ):
                groups[(e.host or "unknown", e.service or "application")].append(e)
        results = []
        for (host, service), requests in groups.items():
            errors = [e for e in requests if 500 <= int(e.attributes.get("status_code", 0)) < 600]
            rate = len(errors) / len(requests)
            if len(errors) >= self.minimum_errors and rate >= self.error_rate:
                results.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        category=EventCategory.APPLICATION,
                        severity=Severity.HIGH,
                        confidence=0.9,
                        summary=f"{len(errors)} of {len(requests)} requests ({rate:.0%}) returned HTTP 5xx for {service}.",
                        root_cause="The application or an upstream dependency is failing while processing requests.",
                        evidence=[
                            Evidence(
                                event_id=e.id,
                                summary=e.message,
                                details={"status_code": e.attributes.get("status_code")},
                            )
                            for e in errors[:20]
                        ],
                        analyst_checks=[
                            "Compare the spike with deployments and dependency health.",
                            "Group errors by route and exception signature.",
                        ],
                        remediation=[
                            "Roll back a confirmed faulty deployment or restore the failing dependency using change controls."
                        ],
                        validation=[
                            "Verify 5xx rate returns to baseline and key transactions succeed."
                        ],
                        limitations=[
                            "HTTP status alone cannot distinguish application defects from dependency failures."
                        ],
                        correlation_key=f"http5xx:{host}:{service}",
                    )
                )
        return results
