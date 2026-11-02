# Data model

## TelemetryEvent

The normalized input envelope contains an immutable identifier, UTC timestamp, source, category, event type, host/service context, human-readable message, typed attributes, and optional raw metadata.

## Finding

A rule emits a finding with a stable rule ID, severity, confidence, summary, likely root cause, evidence, analyst checks, safe remediation, validation, limitations, optional ATT&CK techniques, and a correlation key.

## Incident

Correlation combines one or more findings into an analyst-facing incident while preserving rule IDs and evidence. Incidents have lifecycle status but are never treated as conclusive attribution.
