from cyberguard.core.enums import EventCategory, Severity
from cyberguard.core.models import Evidence, Finding, TelemetryEvent
from cyberguard.detection.base import DetectionRule

SENSITIVE_PREFIXES = ("/etc/", "/usr/bin/", "/usr/sbin/", "c:\\windows\\system32\\")


class SensitiveFileChangeRule(DetectionRule):
    rule_id = "CG-FIM-001"
    title = "Sensitive file changed"

    def evaluate(self, events: list[TelemetryEvent]) -> list[Finding]:
        findings = []
        for event in events:
            path = str(event.attributes.get("path", ""))
            action = str(event.attributes.get("action", "modified")).lower()
            if event.category != EventCategory.FILE_INTEGRITY or not path.lower().startswith(
                SENSITIVE_PREFIXES
            ):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    category=EventCategory.FILE_INTEGRITY,
                    severity=Severity.HIGH,
                    confidence=0.88,
                    summary=f"{path} was {action} on {event.host or 'unknown'}.",
                    root_cause="A security-sensitive operating-system path changed and requires authorization review.",
                    evidence=[
                        Evidence(
                            event_id=event.id,
                            summary=event.message,
                            details={
                                "path": path,
                                "action": action,
                                "hash": event.attributes.get("sha256"),
                            },
                        )
                    ],
                    analyst_checks=[
                        "Compare the change with approved maintenance and verify signer, owner, hash, and process lineage."
                    ],
                    remediation=[
                        "If unauthorized, isolate affected scope and restore from a trusted source under incident procedure."
                    ],
                    validation=[
                        "Confirm the expected hash and ensure no related persistence artifacts remain."
                    ],
                    limitations=[
                        "Legitimate patching and package management commonly modify sensitive paths."
                    ],
                    mitre_techniques=["T1565.001"],
                    correlation_key=f"fim:{event.host or 'unknown'}:{path}",
                )
            )
        return findings
