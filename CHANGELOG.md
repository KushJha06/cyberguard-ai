# Changelog

## 0.9.0 — 2026-10-02

- Expanded the dataset catalog to eight provider-maintained sources with acquisition, licensing, compatibility, coverage and exact upload guidance.
- Rebuilt Configuration telemetry with source-specific upload guidance, safety boundaries, a downloadable example and evidence-led finding details.
- Added Kubernetes workload security checks and corrected automatic routing for SSH, Nginx, generic `.conf` and `.env` inputs.

## 0.8.1 — 2026-10-02

- Added a visible analysis manifest with exact files, adapter, event categories/types, source counts and rule-execution totals.
- Added Loghub-style CSV mappings for Content, Level, Component, EventId and split Date/Time fields.
- Aggregated generic failures into bounded evidence-led incidents and added indicator counts with sampled source records.

## 0.8.0 — 2026-10-02

- Added structured configuration analysis for YAML, TOML, INI/CFG, XML, ENV and properties files.
- Added bounded ZIP, TAR/TAR.GZ and GZIP bundle inspection with traversal and expansion protections.
- Added generic explicit-error triage and Docker, Nginx, secret, debug, anonymous-access and TLS-verification configuration checks.
- Added a dedicated React Configuration workspace and a reproducible dataset-research prompt for Perplexity.

## 0.7.2 — 2026-10-02

- Rebuilt Analyze Telemetry with live API readiness, explicit file validation, parser selection, staged progress, reliable retry and reset controls, clearer errors, and empty-result guidance.
- Added client request timeouts and strengthened CSV ingestion feedback.

## 0.7.1 — 2026-10-02

- Added robust CSV delimiter detection, common column aliases, timestamp parsing, type coercion, category inference, and useful fallback messages for arbitrary tabular exports.
- Added a downloadable CSV template to the React ingestion workspace and API.

## 0.7.0 — 2026-10-02

- Replaced the primary Streamlit experience with a responsive React and TypeScript analyst console built on Vite.
- Added production navigation, command-center charts, live fleet cards, investigation workflow, universal upload, preflight, plugins, datasets, reports, and settings views.
- Added route-level code splitting, typed API contracts, five-second live polling, responsive layouts, and a production Nginx container with same-origin API proxying.
- Retained Streamlit as an optional legacy/reference interface.

## 0.6.0 — 2026-10-02

- Added Plugin API v1 with trusted Python entry-point discovery for independently released adapters and detections.
- Added plugin inventory APIs, load-failure visibility, a professional Integrations & Plugins workspace, and an installable plugin template.
- Added plugin-development documentation, collaboration issue templates, dependency automation, lint/security workflows, and tagged-release package builds.

## 0.5.0 — 2026-10-02

- Added a read-only cross-platform host agent for live CPU, memory, disk, service, health-endpoint, selected-log, SSH configuration, and file-integrity telemetry.
- Added persistent agent heartbeat registration and a five-second auto-refreshing Live Systems console.
- Added disk capacity trend forecasting to warn before the static exhaustion threshold.
- Added optional bearer-token authentication for agents and documented host-side deployment boundaries.

## 0.4.0 — 2026-10-02

- Added universal safe text inspection for unknown file extensions and explicit binary conversion guidance.
- Added post-ingestion diagnosis that classifies likely issues as application, system/infrastructure, configuration, security logs, file integrity, network telemetry, or unclassified logs.
- Added automated preflight checks and an analyst readiness page to surface blockers before work begins.
- Removed the UI extension restriction and added readiness, likely-cause, and before-you-begin guidance after every analysis.

## 0.3.0 — 2026-10-02

- Added optimized SQLite WAL storage, chunked batch writes, filtered pagination, and incident workflow updates.
- Moved CPU-bound ingestion off the async event loop and added gzip, CORS, request IDs, timing headers, dry-run analysis, stats, capabilities, and dataset APIs.
- Added an official-source evaluation dataset catalog and deterministic local benchmark generator.
- Added a dataset laboratory page and working incident status controls.

## 0.2.0 — 2026-10-02

- Rebuilt the Streamlit experience as a professional multi-page analyst console.
- Added memory pressure, service availability, sensitive-file change, and suspicious PowerShell detections.
- Added local playbooks, MITRE ATT&CK context, file-integrity workflow, and Markdown/HTML/JSON reports.
- Added reusable UI components and expanded architecture, data-model, deployment, threat-model, and roadmap documentation.

## 0.1.0 — 2026-10-02

- Initial working MVP with FastAPI and Streamlit interfaces.
- Added CSV, JSON/JSONL, and SSH configuration ingestion.
- Added five deterministic detection modules.
- Added local SQLite persistence, redaction, correlation, tests, and samples.
