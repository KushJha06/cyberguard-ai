from cyberguard.core.enums import EventCategory, Severity
from cyberguard.core.models import Evidence, Finding, TelemetryEvent
from cyberguard.detection.base import DetectionRule

TOKENS = (
    "-enc ",
    "-encodedcommand",
    "frombase64string",
    "downloadstring",
    "invoke-expression",
    "iex(",
)


class SuspiciousPowerShellRule(DetectionRule):
    rule_id = "CG-SEC-002"
    title = "Suspicious PowerShell execution"

    def evaluate(self, events: list[TelemetryEvent]) -> list[Finding]:
        findings = []
        for event in events:
            command = str(event.attributes.get("command_line", event.message))
            matched = [token for token in TOKENS if token in command.lower()]
            if not matched:
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    category=EventCategory.APPLICATION,
                    severity=Severity.HIGH,
                    confidence=min(0.75 + 0.05 * len(matched), 0.95),
                    summary=f"PowerShell command contains suspicious execution patterns on {event.host or 'unknown'}.",
                    root_cause="Encoded or download-and-execute behavior can indicate malicious script execution.",
                    evidence=[
                        Evidence(
                            event_id=event.id,
                            summary=event.message,
                            details={"indicators": matched},
                        )
                    ],
                    analyst_checks=[
                        "Review the full command, parent process, user, script-block logs, network connections, and signer."
                    ],
                    remediation=[
                        "If malicious, contain the endpoint and revoke exposed credentials under incident procedure."
                    ],
                    validation=[
                        "Hunt for the same indicators across endpoints and confirm persistence is absent."
                    ],
                    limitations=[
                        "Administration and software deployment tools can legitimately use encoded PowerShell."
                    ],
                    mitre_techniques=["T1059.001"],
                    correlation_key=f"powershell:{event.host or 'unknown'}",
                )
            )
        return findings
