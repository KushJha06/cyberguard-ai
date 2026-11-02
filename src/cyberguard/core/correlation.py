from collections import defaultdict

from .models import Finding


def group_findings(findings: list[Finding]) -> dict[str, list[Finding]]:
    groups: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        groups[finding.correlation_key].append(finding)
    return dict(groups)
