from .models import Finding, Incident
from .severity import max_severity


def incident_from_findings(findings: list[Finding]) -> Incident:
    if not findings:
        raise ValueError("At least one finding is required")
    primary = max(findings, key=lambda f: f.confidence)

    def unique(values: list[str]) -> list[str]:
        return list(dict.fromkeys(values))

    return Incident(
        title=primary.title,
        category=primary.category,
        severity=max_severity(*(f.severity for f in findings)),
        confidence=max(f.confidence for f in findings),
        summary=" ".join(unique([f.summary for f in findings])),
        root_cause=primary.root_cause,
        evidence=[e for f in findings for e in f.evidence],
        analyst_checks=unique([x for f in findings for x in f.analyst_checks]),
        remediation=unique([x for f in findings for x in f.remediation]),
        validation=unique([x for f in findings for x in f.validation]),
        limitations=unique([x for f in findings for x in f.limitations]),
        mitre_techniques=unique([x for f in findings for x in f.mitre_techniques]),
        rule_ids=unique([f.rule_id for f in findings]),
        correlation_key=primary.correlation_key,
        event_count=sum(len(f.evidence) for f in findings),
    )
