from .enums import Severity

_ORDER = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


def max_severity(*values: Severity) -> Severity:
    return max(values, key=_ORDER.__getitem__)
