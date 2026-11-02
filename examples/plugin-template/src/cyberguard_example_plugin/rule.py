from cyberguard.sdk import (
    DetectionRule,
    EventCategory,
    Evidence,
    Finding,
    Severity,
    TelemetryEvent,
)


class HighCPURule(DetectionRule):
    rule_id = "EXAMPLE-SYS-001"
    title = "Example sustained CPU threshold"

    def evaluate(self, events: list[TelemetryEvent]) -> list[Finding]:
        findings = []
        for event in events:
            value = event.attributes.get("cpu_used_percent")
            if event.event_type != "host_health" or not isinstance(value, (int, float)) or value < 95:
                continue
            host = event.host or "unknown"
            findings.append(Finding(rule_id=self.rule_id, title=self.title,
                category=EventCategory.SYSTEM, severity=Severity.MEDIUM, confidence=.7,
                summary=f"CPU utilization is {value}% on {host}.",
                root_cause="The host reported CPU utilization above the example threshold.",
                evidence=[Evidence(event_id=event.id, summary=event.message,
                    details={"cpu_used_percent": value})],
                analyst_checks=["Confirm utilization across multiple samples and identify top consumers."],
                remediation=["Correct the confirmed workload cause or scale through change control."],
                validation=["Confirm utilization and service latency return to baseline."],
                limitations=["A single sample does not establish sustained pressure."],
                correlation_key=f"example-cpu:{host}"))
        return findings
