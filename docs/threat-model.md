# Threat model

## Protected assets

Telemetry confidentiality, evidence integrity, analyst trust, local credentials, and host availability.

## Principal risks

- Malicious or malformed uploads attempting parser exploitation or resource exhaustion
- Secrets or personal information embedded in telemetry
- Unauthenticated access when the MVP API is exposed beyond a trusted host
- Misleading detection output causing unsafe remediation
- Tampering with the local SQLite evidence store

## Current controls

Upload size limits, allow-listed text adapters, no content execution, parameterized SQL, Pydantic validation, best-effort redaction, explicit limitations, and no autonomous remediation.

## Deployment obligations

Place shared deployments behind TLS and authentication, restrict filesystem permissions, back up and monitor the evidence store, configure retention, and treat all reports as sensitive. The built-in API is not suitable for direct Internet exposure.
