# Architecture

CyberGuard uses a deterministic, local-first analysis pipeline:

1. **Adapters** parse source formats into `TelemetryEvent`.
2. **Redaction** removes common secret fields and inline credentials before persistence.
3. **Detection rules** independently produce evidence-led `Finding` records.
4. **Correlation** groups findings with stable correlation keys.
5. **Incident management** combines findings without hiding rule provenance.
6. **SQLite storage** persists normalized events and incidents locally.
7. **FastAPI and Streamlit** expose the same application service.

## Trust boundaries

Uploaded files are untrusted. The MVP bounds upload size, does not execute content, uses parameterized SQL, and only parses supported text formats. It never performs automated remediation. Deploy behind authenticated access before use beyond a trusted workstation.

## Extension points

Implement `Adapter.parse()` for new telemetry sources and `DetectionRule.evaluate()` for new analytics, then register the implementation in the corresponding default registry. Detection output is constrained by Pydantic models so every result carries evidence, checks, remediation, validation, and limitations.
