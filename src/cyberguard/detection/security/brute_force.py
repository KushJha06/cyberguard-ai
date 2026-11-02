from collections import defaultdict, deque
from datetime import timedelta

from cyberguard.core.enums import EventCategory, Severity
from cyberguard.core.models import Evidence, Finding, TelemetryEvent
from cyberguard.detection.base import DetectionRule


class SSHBruteForceRule(DetectionRule):
    rule_id = "CG-SEC-001"
    title = "Possible SSH brute-force attack"

    def __init__(self, threshold: int = 5, window_minutes: int = 10) -> None:
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)

    def evaluate(self, events: list[TelemetryEvent]) -> list[Finding]:
        groups = defaultdict(list)
        for event in events:
            text = event.message.lower()
            if event.category == EventCategory.AUTHENTICATION and (
                event.attributes.get("outcome") == "failure" or "failed password" in text
            ):
                key = (str(event.attributes.get("source_ip", "unknown")), event.host or "unknown")
                groups[key].append(event)
        findings = []
        for (source_ip, host), attempts in groups.items():
            attempts.sort(key=lambda event: event.timestamp)
            window: deque[TelemetryEvent] = deque()
            matched: list[TelemetryEvent] = []
            for attempt in attempts:
                window.append(attempt)
                while window and attempt.timestamp - window[0].timestamp > self.window:
                    window.popleft()
                if len(window) >= self.threshold:
                    matched = list(window)
                    break
            if matched:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        category=EventCategory.AUTHENTICATION,
                        severity=Severity.HIGH,
                        confidence=0.9,
                        summary=f"{len(matched)} failed SSH logins from {source_ip} against {host}.",
                        root_cause="Repeated authentication failures indicate credential guessing or an automated brute-force attempt.",
                        evidence=[
                            Evidence(
                                event_id=e.id, summary=e.message, details={"source_ip": source_ip}
                            )
                            for e in matched
                        ],
                        analyst_checks=[
                            "Confirm whether the source IP belongs to an authorized scanner or administrator.",
                            "Review successful logins after the failure burst.",
                        ],
                        remediation=[
                            "Restrict SSH exposure and enable rate limiting or fail2ban after approval.",
                            "Prefer key-based authentication and disable unused accounts.",
                        ],
                        validation=[
                            "Verify the failure rate returns to baseline.",
                            "Confirm no suspicious successful session followed the attempts.",
                        ],
                        limitations=[
                            "NAT or shared jump hosts can make many users appear under one source IP."
                        ],
                        mitre_techniques=["T1110.001"],
                        correlation_key=f"ssh-bruteforce:{source_ip}:{host}",
                    )
                )
        return findings
