from cyberguard.core.enums import EventCategory, Severity
from cyberguard.core.models import Evidence, Finding, TelemetryEvent
from cyberguard.detection.base import DetectionRule


class DiskFullRule(DetectionRule):
    rule_id = "CG-SYS-001"
    title = "Disk-space exhaustion"

    def __init__(self, threshold_percent: float = 90) -> None:
        self.threshold = threshold_percent

    def evaluate(self, events: list[TelemetryEvent]) -> list[Finding]:
        results = []
        for e in events:
            used = e.attributes.get("disk_used_percent")
            if used is None and e.event_type == "disk_usage":
                used = e.attributes.get("value")
            try:
                used = float(used)
            except (TypeError, ValueError):
                continue
            if used >= self.threshold:
                severity = Severity.CRITICAL if used >= 98 else Severity.HIGH
                host = e.host or "unknown"
                mount = str(e.attributes.get("mount", "/"))
                results.append(Finding(rule_id=self.rule_id, title=self.title, category=EventCategory.SYSTEM,
                    severity=severity, confidence=0.98, summary=f"Disk usage is {used:.1f}% on {host}:{mount}.",
                    root_cause="Filesystem capacity is nearly exhausted, which can interrupt writes and dependent services.",
                    evidence=[Evidence(event_id=e.id, summary=e.message, details={"used_percent": used, "mount": mount})],
                    analyst_checks=["Identify the largest recent files and directories.", "Check log rotation and inode utilization."],
                    remediation=["Remove or archive verified expendable data after approval.", "Correct retention/rotation policy or expand capacity."],
                    validation=["Confirm usage is below the configured threshold.", "Verify affected services can write successfully."],
                    limitations=["A single metric cannot identify which data is safe to remove."],
                    correlation_key=f"disk:{host}:{mount}"))
        return results
