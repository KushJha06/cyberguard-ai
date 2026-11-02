# CyberGuard detection upload pack

These are deliberately synthetic, non-sensitive fixtures for validating CyberGuard. Do not deploy the insecure SSH configuration.

## Fastest demonstration

1. Upload `00_all_csv_detections.csv` with **Auto-detect** or **CSV telemetry**.
2. It accepts 24 events and creates 9 incidents: every CSV-compatible detection.
3. Upload `09_insecure_sshd.conf` with **Auto-detect** or **OpenSSH configuration** to create the tenth incident.

## Individual fixtures

| File | Expected rule | Expected incident |
|---|---|---|
| `01_disk_exhaustion.csv` | `CG-SYS-001` | Disk-space exhaustion |
| `02_memory_pressure.csv` | `CG-SYS-002` | Sustained memory pressure |
| `03_service_unavailable.csv` | `CG-SYS-003` | Service unavailable |
| `04_http_500_spike.csv` | `CG-APP-001` | HTTP 5xx error spike |
| `05_database_pool_failure.csv` | `CG-APP-002` | Database connection-pool failure |
| `06_ssh_brute_force.csv` | `CG-SEC-001` | Possible SSH brute-force attack |
| `07_suspicious_powershell.csv` | `CG-SEC-002` | Suspicious PowerShell execution |
| `08_sensitive_file_change.csv` | `CG-FIM-001` | Sensitive file changed |
| `09_insecure_sshd.conf` | `CG-CFG-001` | Insecure SSH configuration |
| `10_capacity_forecast.csv` | `CG-SYS-004` | Projected disk-capacity exhaustion |

A successful upload may create zero incidents if values do not meet a rule threshold. These fixtures are intentionally above the current thresholds and have been verified against CyberGuard v0.7.2.
