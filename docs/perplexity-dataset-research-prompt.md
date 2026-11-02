# Prompt for Perplexity: CyberGuard evaluation datasets

Copy the complete prompt below into Perplexity.

---

I am building **CyberGuard AI**, an Apache-2.0, local-first, open-source diagnostics and cybersecurity triage platform. I need authoritative, legally reusable third-party datasets for realistic end-to-end evaluation. Research the current official sources and give me a cited, reproducible dataset acquisition plan.

CyberGuard accepts CSV, JSON, JSONL, plain logs, YAML/YML, TOML, INI/CFG, XML, ENV/properties, SSH configuration, ZIP, TAR/TAR.GZ and GZIP bundles. Its normalized event fields are:

- `timestamp`
- `source`
- `category`: system, application, authentication, network, configuration, file_integrity, unknown
- `event_type`
- `host`
- `service`
- `message`
- `attributes` object

Current detections and evaluation targets:

1. SSH brute force / repeated failed authentication
2. Suspicious or encoded PowerShell execution
3. Disk-space exhaustion
4. Forecasted disk-capacity exhaustion from time-series growth
5. Memory pressure
6. Service unavailable or failed health endpoint
7. HTTP 5xx error-rate spike
8. Database connection-pool exhaustion/timeouts
9. Generic fatal/error/exception/permission/connection-refused indicators
10. Insecure SSH configuration
11. Risky structured configuration: plaintext secret-like keys, debug mode, disabled TLS verification, anonymous access, Docker privileged mode, host networking, root user, Docker socket mounts, unpinned images, Nginx server tokens/autoindex/legacy TLS/wildcard CORS
12. Sensitive file changes under Linux system paths and Windows System32

Find datasets covering all of these domains:

- Linux system logs and resource metrics
- Windows Security, Sysmon and PowerShell logs
- Apache/Nginx/application request and error logs
- Database/application dependency failures
- SSH/OpenSSH authentication logs
- Network flow and intrusion datasets
- File-integrity events from Wazuh, auditd, Sysmon or equivalent
- Real or representative SSH, Docker Compose, Kubernetes, Nginx and application configuration corpora
- Multivariate server metrics with labeled faults or anomalies
- Multi-source enterprise host/network correlation data

For every candidate dataset, provide a table with:

1. Exact dataset name and version
2. Official publisher/maintainer
3. Official landing page and direct download location
4. License or exact usage restrictions, including whether redistribution and commercial use are allowed
5. Collection year and environment
6. Compressed and expanded size
7. File formats
8. Record count and time span
9. Labels/ground truth and attack or failure classes
10. Which CyberGuard rules/features it can validate
11. Important quality problems, leakage, duplication, known corrections or realism limitations
12. Required preprocessing and field mapping into the CyberGuard event schema
13. Whether a small official sample under 100 MB exists
14. Checksums or provenance verification provided by the publisher
15. Recommended train/tuning/evaluation split that avoids leakage

Source requirements:

- Prefer university, government, standards-body, original research-group, Zenodo or official GitHub sources.
- Do not recommend an unofficial Kaggle mirror when an official source exists.
- Clearly distinguish permissively licensed, research-only, registration-required and unclear-license datasets.
- Do not claim that a dataset is open source merely because it is publicly downloadable.
- Cite the source for every license, size, schema and record-count claim.
- Flag datasets that include packet payloads, personal data, secrets or other sensitive material.
- Mention any dataset known to contain labeling defects or unrealistic synthetic traffic.

Then produce:

A. A **minimum practical validation bundle** covering all 12 detections with the fewest datasets.
B. A **quick CI bundle** under 500 MB total.
C. A **full research benchmark bundle** for offline evaluation.
D. A prioritized adapter roadmap for CyberGuard: which source adapter to implement first and why.
E. Concrete mapping examples for at least one row/event from each recommended dataset into the normalized CyberGuard JSON schema.
F. A shell-command acquisition plan using official URLs, with checksum verification where available. Do not invent direct URLs; if terms require manual acceptance, say so.
G. A reproducibility manifest template containing source URL, retrieval date, upstream checksum, local checksum, preprocessing version, row counts, rejected rows, label mapping and split definition.

End with a coverage matrix whose rows are the recommended datasets and columns are the 12 CyberGuard detection targets. Mark each cell as Direct, Partial, Fixture-only or Not covered.

Use information current as of today and include clickable citations.

---
