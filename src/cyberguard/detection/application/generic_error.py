import re
from collections import defaultdict

from cyberguard.core.enums import EventCategory, Severity
from cyberguard.core.models import Evidence, Finding, TelemetryEvent
from cyberguard.detection.base import DetectionRule

_ERROR = re.compile(r"\b(fatal|panic|exceptions?|traceback|segmentation fault|permission denied|connection refused|timed?\s*out|errors?|failed|failure)\b", re.I)
_EXCLUSIONS = ("0 errors", "no error", "error_count=0", "without error", "0 failed", "no failures")
_ERROR_LEVELS = {"error", "err", "fatal", "critical", "crit", "alert", "emergency", "failed", "failure"}


class GenericErrorRule(DetectionRule):
    rule_id = "CG-APP-003"
    title = "Unhandled error indicators"

    def evaluate(self, events: list[TelemetryEvent]) -> list[Finding]:
        groups: dict[tuple[str, str, str, str], list[tuple[TelemetryEvent, str]]] = defaultdict(list)
        for event in events:
            if event.category in {EventCategory.AUTHENTICATION, EventCategory.CONFIGURATION,
                EventCategory.FILE_INTEGRITY} or event.event_type in {"service_status", "disk_usage", "memory_usage"}:
                continue
            text = event.message
            lowered = text.lower()
            level = str(event.attributes.get("log_level", "")).lower()
            match = _ERROR.search(text)
            indicator = match.group(1).lower() if match else level if level in _ERROR_LEVELS else ""
            if not indicator or any(exclusion in lowered for exclusion in _EXCLUSIONS):
                continue
            if any(token in lowered for token in ("connection pool exhausted", "timeout acquiring connection", "pool timeout")):
                continue
            category = event.category if event.category != EventCategory.UNKNOWN else EventCategory.APPLICATION
            key = (event.host or "unknown", event.service or "unknown", category.value, indicator)
            groups[key].append((event, indicator))
        findings = []
        for (host, service, category_value, indicator), matches in groups.items():
            category = EventCategory(category_value)
            sample = matches[:50]
            findings.append(Finding(rule_id=self.rule_id, title=self.title, category=category,
                severity=Severity.HIGH if indicator in {"fatal", "panic", "critical", "crit", "emergency"} else Severity.MEDIUM,
                confidence=min(.62 + .03 * (len(matches) - 1), .9),
                summary=f"Found {len(matches)} {indicator} indicator(s) for {service} on {host}.",
                root_cause="The supplied data contains explicit failure indicators, but the exact cause requires surrounding context and dependency checks.",
                evidence=[Evidence(event_id=event.id, summary=event.message,
                    details={"indicator": item_indicator, "source": event.source,
                        "line": event.attributes.get("line_number") or event.attributes.get("csv_row")})
                    for event, item_indicator in sample],
                analyst_checks=["Review records before and after the sampled failures and correlate timestamps with deployments, dependencies, capacity and permissions.",
                    "Group failures by component, event template, error code and host to identify the dominant signature."],
                remediation=["Apply the component-specific fix only after confirming the failing layer and preserving rollback access."],
                validation=["Repeat the affected operation and confirm the failure signature no longer occurs under representative conditions."],
                limitations=[f"Only the first {len(sample)} of {len(matches)} matching records are attached as evidence.",
                    "Generic failure detection cannot establish attribution without structured operational context."],
                correlation_key=f"generic-error:{host}:{service}:{indicator}"))
        return findings
