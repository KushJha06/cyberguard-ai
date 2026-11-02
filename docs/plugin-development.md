# Plugin development

CyberGuard Plugin API v1 supports trusted, separately packaged adapters and detection rules through standard Python entry points. Community packages can release independently while keeping the core dependency graph small.

## Adapter contract

Subclass `cyberguard.ingestion.base.Adapter`, provide a globally unique `name`, declare supported extensions when useful, and implement `parse(path) -> list[TelemetryEvent]`. Treat all input as untrusted: bound records and bytes, never execute content, preserve timestamps, and document rejected rows.

## Detection contract

Subclass `cyberguard.detection.base.DetectionRule`, provide a stable namespaced `rule_id` and `title`, and implement `evaluate(events) -> list[Finding]`. Every finding must include evidence, confidence, likely root cause, analyst checks, safe remediation, validation, limitations, and a stable correlation key.

## Entry points

```toml
[project.entry-points."cyberguard.adapters"]
acme_zeek = "acme_cyberguard.zeek:ZeekAdapter"

[project.entry-points."cyberguard.detections"]
acme_dns_tunnel = "acme_cyberguard.rules:DNSTunnelRule"
```

The entry point may resolve to an instance or a zero-argument class. CyberGuard validates the base type, reports load failures through `/api/v1/plugins`, and exposes the inventory in the UI.

## Compatibility

Declare the supported core range in your package metadata, for example `cyberguard-ai>=0.6,<0.7`, and state the Plugin API version in your README. Import stable types from `cyberguard.sdk`: `TelemetryEvent`, `Finding`, `Evidence`, `Adapter`, `DetectionRule`, enums, and `PLUGIN_API_VERSION`. Avoid importing internal storage, UI or service objects.

## Security

Plugins execute inside the API process and are not sandboxed. Install only trusted, reviewed packages; pin versions and hashes; run tests and dependency scans; do not perform network access or subprocess execution during import. Plugin loading can be disabled with `CYBERGUARD_ENABLE_EXTERNAL_PLUGINS=false`.

## Review checklist

- Unique package, adapter and rule IDs
- Tests for valid, malformed, oversized and empty input
- Deterministic output and bounded memory use
- No secrets in fixtures
- License and provenance for bundled samples
- Documented false positives, limitations and performance
- `ruff check` and `pytest` passing

See `examples/plugin-template` for a minimal installable detection plugin.
