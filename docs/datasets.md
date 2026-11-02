# Evaluation dataset catalog

CyberGuard does not automatically download or redistribute third-party data. Use the provider-maintained links below, review the current terms, retain provenance/checksums, and start with a bounded sample.

| Source | Official provider page | Acquisition | Current upload path |
|---|---|---|---|
| Loghub 2.0 | https://github.com/logpai/loghub-2.0 | https://zenodo.org/records/8275861 | Upload a `*_2k.log_structured.csv` or small raw `.log` directly. |
| OS-Metrics V1.0 | https://zenodo.org/records/17981352 | https://zenodo.org/records/17981352/files/OSMetrics.zip?download=1 | Extract and upload a CSV slice up to the event limit; canonicalize metric columns where needed. |
| OTRF Security Datasets | https://github.com/OTRF/Security-Datasets | https://github.com/OTRF/Security-Datasets/tree/master/datasets | Select a small JSON export. Convert EVTX/PCAP first. |
| LANL Unified Host and Network | https://csr.lanl.gov/data/2017/ | Provider page | Map a bounded JSONL/CSV time slice into CyberGuard fields. |
| CIC-IDS2017 | https://www.unb.ca/cic/datasets/ids-2017.html | Provider page | Flow CSV requires a dedicated mapping; PCAP requires an adapter. |
| UNSW-NB15 | https://research.unsw.edu.au/projects/unsw-nb15-dataset | Provider page | Upload only a mapped CSV sample. |
| ToN-IoT | https://research.unsw.edu.au/projects/toniot-datasets | Provider page | Select one source and map timestamp, host, service, message, metrics and label. |
| Splunk Attack Data | https://github.com/splunk/attack_data | https://github.com/splunk/attack_data/tree/master/datasets | Convert scenario event exports to JSON/CSV; EVTX requires conversion. |

The live **Dataset catalog** displays compatibility as **Direct upload**, **Sample / transform**, **Transform first**, or **Adapter needed**, along with concrete upload instructions and expected CyberGuard coverage.

## Recommended first evaluation

1. Download a Loghub 2.0 2k structured sample.
2. Upload the CSV through **Analyze telemetry**.
3. Confirm the analysis manifest shows the expected filename, CSV adapter, 2,000 events, category distribution and twelve rules evaluated.
4. Review grouped error evidence rather than treating an anomaly label as a proven root cause.
5. Use OS-Metrics next for system-metric normalization and OTRF JSON exports for Windows/PowerShell adapter work.

## Reproducibility requirements

Record source URL, retrieval date, upstream and local checksums, exact files, preprocessing version, row counts, label mapping, rejected-row count, and train/evaluation split. Do not tune thresholds on the final evaluation split.

## Configuration uploads

Use **Configuration telemetry** for current configuration state, not operational logs:

- SSH: `/etc/ssh/sshd_config`, `sshd_config.conf`
- Docker: `docker-compose.yml`, `compose.yaml`
- Kubernetes: Pod, Deployment, DaemonSet, StatefulSet, Job or CronJob YAML
- Nginx: `nginx.conf` and related include files in a bounded archive
- Applications: `application.yml`, `config.toml`, `app.ini`, `.env`, `*.properties`, XML configuration

Preserve recognizable filenames so the correct specialized checker can be selected. Use placeholders for secret values and never upload private keys, executable content, encrypted archives, production database dumps, or files you are not authorized to inspect.

## Data handling

Public does not mean non-sensitive. Store large datasets outside Git, mount them read-only where possible, use strict filesystem permissions, and do not expose raw payloads through the UI. Archives are inspected without execution and are bounded to 100 members and 50 MB expanded content.
