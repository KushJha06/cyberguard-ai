# Real-time host agent

`cyberguard-agent` is a read-only polling agent intended to run on each monitored host. It sends normalized telemetry to the central API over HTTP(S); it does not restart services, kill processes, edit configuration, or delete files.

## Collected by default

- CPU utilization, one-minute load, process count and boot time
- Memory, available bytes and swap utilization
- Mounted filesystem utilization and free bytes
- OpenSSH configuration snapshot when readable

## Opt-in collection

- Named service state through `CYBERGUARD_AGENT_SERVICES`
- HTTP application health endpoints through `CYBERGUARD_AGENT_HEALTH_URLS`
- New lines from selected logs through `CYBERGUARD_AGENT_LOG_PATHS`
- SHA-256 change detection for selected files through `CYBERGUARD_AGENT_WATCH_PATHS`

Comma-separate multiple values. Configure `CYBERGUARD_AGENT_TOKEN` with the same strong value on API and agents. Put the API behind TLS and network controls in any non-local deployment.

## Capacity warning

The agent retains the previous sample in memory and estimates disk growth. When a rising filesystem is projected to fill within four hours, `CG-SYS-004` emits an early-warning finding. A two-point projection can be affected by temporary bursts, so the analyst must confirm that growth persists.

## Containers

Run the agent directly on the host for host-level visibility. An agent inside an ordinary container sees the container namespace and mounted filesystems, not a complete host view. Avoid privileged containers; grant only the minimum read permissions needed for selected logs and configuration.
