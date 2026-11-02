import re
from typing import Any

KEY_PATTERN = re.compile(r"(password|passwd|secret|token|api[_-]?key|authorization)", re.I)
VALUE_PATTERNS = [
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)((?:password|passwd|secret|token)\s*[=:]\s*)\S+"),
]


def redact_text(value: str) -> str:
    result = value
    for pattern in VALUE_PATTERNS:
        result = pattern.sub(r"\1[REDACTED]", result)
    return result


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: "[REDACTED]" if KEY_PATTERN.search(str(k)) else redact(v) for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
