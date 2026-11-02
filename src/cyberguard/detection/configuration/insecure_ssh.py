from cyberguard.core.enums import EventCategory, Severity
from cyberguard.core.models import Evidence, Finding, TelemetryEvent
from cyberguard.detection.base import DetectionRule


class InsecureSSHRule(DetectionRule):
    rule_id = "CG-CFG-001"
    title = "Insecure SSH configuration"

    def evaluate(self, events: list[TelemetryEvent]) -> list[Finding]:
        results = []
        for e in events:
            if e.event_type != "ssh_config_snapshot":
                continue
            directives = {
                str(k).lower(): str(v).lower()
                for k, v in e.attributes.get("directives", {}).items()
            }
            issues = []
            if directives.get("permitrootlogin") in {"yes", "without-password"}:
                issues.append("Root login is permitted")
            if directives.get("passwordauthentication") == "yes":
                issues.append("Password authentication is enabled")
            if directives.get("permitemptypasswords") == "yes":
                issues.append("Empty passwords are permitted")
            if directives.get("protocol") == "1":
                issues.append("Legacy SSH protocol 1 is configured")
            if not issues:
                continue
            severity = (
                Severity.CRITICAL
                if any("Empty" in x or "protocol 1" in x for x in issues)
                else Severity.HIGH
            )
            results.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    category=EventCategory.CONFIGURATION,
                    severity=severity,
                    confidence=0.96,
                    summary="; ".join(issues) + ".",
                    root_cause="The SSH daemon configuration permits authentication modes that increase remote-access risk.",
                    evidence=[Evidence(event_id=e.id, summary=issue) for issue in issues],
                    analyst_checks=[
                        "Confirm effective settings with `sshd -T` before changing configuration.",
                        "Ensure emergency access and a tested key-based account exist.",
                    ],
                    remediation=[
                        "Stage hardened settings, validate with `sshd -t`, then reload through change control.",
                        "Set PermitRootLogin no and prefer PasswordAuthentication no where operationally feasible.",
                    ],
                    validation=[
                        "Run `sshd -t` and `sshd -T`, then test a new authorized session before closing the old one."
                    ],
                    limitations=[
                        "Included files and command-line overrides can change the effective configuration."
                    ],
                    mitre_techniques=["T1021.004"],
                    correlation_key=f"ssh-config:{e.host or 'unknown'}",
                )
            )
        return results
