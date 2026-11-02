# CyberGuard AI

CyberGuard AI is an open-source, local-first system diagnostics and cybersecurity incident-triage platform. It turns operational and security telemetry into explainable, evidence-led incidents without taking autonomous action on your systems.

> **Safety boundary:** CyberGuard does not block IPs, restart services, alter configurations, or delete files. It supplies likely root cause, evidence, analyst checks, safe remediation guidance, validation steps, and limitations.

## Working MVP

- FastAPI ingestion and incident APIs with OpenAPI docs
- React and TypeScript analyst console with real-time fleet monitoring and investigation workflows
- Common Pydantic telemetry, finding, evidence, and incident models
- CSV, JSON/JSONL, text/log, SSH, YAML, TOML, INI/CFG/CONF, XML, ENV/properties and bounded archive adapters
- Preflight readiness checks and post-ingestion issue-domain diagnosis
- Twelve deterministic detections:
  - SSH brute force (`T1110.001`)
  - Suspicious PowerShell (`T1059.001`)
  - Disk-space exhaustion, capacity forecasting and memory pressure
  - Service unavailability
  - HTTP 5xx application-error spike
  - Database connection-pool failure
  - Generic fatal/error/exception triage
  - Insecure SSH configuration (`T1021.004` context)
  - Risky Docker, Kubernetes, Nginx and structured application configuration
  - Sensitive-file change (`T1565.001`)
- Professional multi-page analyst console with investigation, file-integrity, knowledge, and reporting workspaces
- Correlation, secret redaction, local SQLite persistence, and Markdown/HTML/JSON reports
- Unit/integration tests and sample telemetry

## Open plugin ecosystem

CyberGuard Plugin API v1 discovers trusted installed packages through standard Python entry points:

```toml
[project.entry-points."cyberguard.adapters"]
my_source = "my_package.adapter:MyAdapter"

[project.entry-points."cyberguard.detections"]
my_rule = "my_package.rule:MyDetectionRule"
```

Plugins appear in **Integrations & Plugins** and `/api/v1/plugins`. See [plugin development](docs/plugin-development.md) and the installable [plugin template](examples/plugin-template). Plugins run inside the API process; review and pin packages before installation, or disable discovery with `CYBERGUARD_ENABLE_EXTERNAL_PLUGINS=false`.

## Real-time host monitoring

Install CyberGuard on each monitored host and point the read-only agent at the API:

```bash
cyberguard-agent --api-url http://CYBERGUARD-SERVER:8000 --interval 30
```

Optional environment variables select services, application health endpoints, logs and files without granting CyberGuard remediation privileges:

```bash
CYBERGUARD_AGENT_SERVICES=nginx,postgresql
CYBERGUARD_AGENT_HEALTH_URLS=http://localhost:8080/health
CYBERGUARD_AGENT_LOG_PATHS=/var/log/syslog,/var/log/nginx/error.log
CYBERGUARD_AGENT_WATCH_PATHS=/etc/ssh/sshd_config,/etc/passwd
CYBERGUARD_AGENT_TOKEN=replace-with-a-strong-shared-secret
```

Open **Live Systems** for a five-second auto-refreshing fleet view. Run the agent on the host; a containerized agent sees the container rather than the host unless explicitly and securely configured otherwise. CyberGuard remains advisory and never restarts services, kills processes, deletes files or edits configuration.

## Quick start

Requires Python 3.11 or newer.

### PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

### macOS/Linux

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

Start the API:

```bash
uvicorn cyberguard.api.app:app --reload --port 8000
```

Open API docs at <http://localhost:8000/docs>. In a second terminal, start the UI:

```bash
streamlit run src/cyberguard/ui/Home.py
```

Open <http://localhost:8501>.

## Try the samples

Upload `data/samples/system.csv` with the `csv` adapter, or run:

```bash
cyberguard data/samples/system.csv --adapter csv
cyberguard data/samples/auth.csv --adapter csv
cyberguard data/samples/sshd_config --adapter ssh_config
```

Direct event ingestion:

```bash
curl -X POST http://localhost:8000/api/v1/ingest/events \
  -H 'content-type: application/json' \
  -d '{"events":[{"source":"node-exporter","category":"system","event_type":"disk_usage","host":"web-1","message":"Disk usage high","attributes":{"disk_used_percent":96,"mount":"/"}}]}'
```

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Readiness, version, adapters/rules, event count |
| `GET` | `/api/v1/preflight` | Filesystem, capacity, policy, and readiness checks |
| `GET` | `/api/v1/agents` | Live and stale monitored-system status |
| `POST` | `/api/v1/agents/heartbeat` | Agent telemetry heartbeat and analysis |
| `GET` | `/api/v1/stats` | Aggregate event and incident statistics |
| `GET` | `/api/v1/rules` | Loaded rule capabilities |
| `GET` | `/api/v1/adapters` | Loaded ingestion capabilities |
| `GET` | `/api/v1/datasets` | Official-source evaluation dataset catalog |
| `POST` | `/api/v1/ingest/events` | Submit normalized events; use `persist=false` for dry runs |
| `POST` | `/api/v1/ingest/file` | Upload telemetry, structured configuration, text logs or bounded archives |
| `GET` | `/api/v1/incidents` | Paginated list with severity/status filters |
| `GET` | `/api/v1/incidents/{id}` | Retrieve an incident |
| `PATCH` | `/api/v1/incidents/{id}/status` | Update analyst workflow status |

## CSV schema

Recognized columns are `timestamp`, `source`, `category`, `event_type`, `host`, `service`, and `message`. Additional columns become typed event attributes. Supported categories include `system`, `application`, `authentication`, `network`, `configuration`, and `file_integrity`.

## Core flow

```text
Log / Config / File Event
          ↓
        Adapter
          ↓
Normalized TelemetryEvent
          ↓
  Redaction + Persistence
          ↓
    Detection Rules
          ↓
 Incident Correlation
          ↓
Dashboard / API / Report
```

## Performance and dataset evaluation

The backend uses SQLite WAL mode, batched transactions, chunked inserts, bounded ingestion, gzip responses, async thread offloading for parsing/detection, linear-time SSH correlation, archive expansion limits, and route-level frontend code splitting. Benchmark performance is hardware- and dataset-dependent; measure with representative data before production sizing.

Generate deterministic evaluation telemetry:

```bash
python scripts/generate_benchmark.py
cyberguard data/samples/benchmark.json --adapter json
```

See [the dataset catalog](docs/datasets.md) or the live Dataset Catalog page for verified Loghub 2.0, OS-Metrics, OTRF Security Datasets, LANL, CIC-IDS2017, UNSW-NB15, ToN-IoT, and Splunk Attack Data provider links, licenses, compatibility labels, and exact upload preparation.

## Test and lint

```bash
pytest
ruff check src tests scripts
```

## Docker Compose

```bash
docker compose up --build
```

The API is exposed on port 8000 and the production React console on port 3000. Nginx serves the optimized frontend and proxies same-origin API requests. Data persists under `./data`.

## Scope and limitations

This MVP uses deterministic rules and batch-level correlation. It does not yet provide authentication, tenant isolation, distributed workers, live agents, automated containment, or an LLM analyst. Put the API behind authentication and TLS before any shared deployment. Redaction is best-effort; telemetry must still be handled as sensitive data.

See [architecture](docs/architecture.md) and [security policy](SECURITY.md).

## License

Apache-2.0
