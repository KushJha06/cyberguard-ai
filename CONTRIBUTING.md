# Contributing

1. Create a focused branch and add tests for behavioral changes.
2. Install with `pip install -e ".[dev]"`.
3. Run `pytest` and `ruff check src tests` before opening a pull request.
4. Keep detections deterministic and ensure every finding includes evidence, checks, remediation, validation, and limitations.
5. Never commit real credentials, personal data, or production telemetry.

New adapters should implement `ingestion.base.Adapter`; new detections should implement `detection.base.DetectionRule` and be registered explicitly.
