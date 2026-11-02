from datetime import UTC, datetime, timedelta

from cyberguard.core.models import TelemetryEvent


def complete_demo_events() -> list[TelemetryEvent]:
    """Deterministic events that exercise every built-in detection rule."""
    start = datetime(2026, 10, 2, 8, 0, tzinfo=UTC)
    raw: list[dict] = []
    for index in range(5):
        raw.append({"timestamp": start + timedelta(seconds=index * 30), "source": "demo-sshd",
            "category": "authentication", "event_type": "login", "host": "edge-01", "service": "ssh",
            "message": "Failed password for invalid user", "attributes": {"source_ip": "203.0.113.42", "outcome": "failure"}})
    raw.extend([
        {"timestamp": start, "source": "demo-metrics", "category": "system", "event_type": "disk_usage",
            "host": "db-01", "message": "Database volume is nearly full",
            "attributes": {"disk_used_percent": 96.4, "mount": "/var/lib/postgresql"}},
        {"timestamp": start, "source": "demo-metrics", "category": "system", "event_type": "memory_usage",
            "host": "api-01", "message": "Sustained memory utilization detected",
            "attributes": {"memory_used_percent": 95.2}},
        {"timestamp": start, "source": "demo-systemd", "category": "system", "event_type": "service_status",
            "host": "web-01", "service": "nginx", "message": "nginx entered failed state",
            "attributes": {"service_state": "failed"}},
        {"timestamp": start, "source": "demo-sysmon", "category": "application", "event_type": "process_start",
            "host": "win-01", "message": "PowerShell process started with encoded command",
            "attributes": {"command_line": "powershell.exe -EncodedCommand SQBFAFgA", "parent": "winword.exe"}},
        {"timestamp": start, "source": "demo-ssh-config", "category": "configuration",
            "event_type": "ssh_config_snapshot", "host": "edge-01", "message": "SSH configuration snapshot",
            "attributes": {"directives": {"permitrootlogin": "yes", "passwordauthentication": "yes"}}},
        {"timestamp": start, "source": "demo-fim", "category": "file_integrity", "event_type": "file_change",
            "host": "edge-01", "message": "Sensitive authentication file modified",
            "attributes": {"path": "/etc/passwd", "action": "modified", "sha256": "demo-hash"}},
    ])
    for index in range(10):
        status = 500 if index < 5 else 200
        raw.append({"timestamp": start + timedelta(seconds=index), "source": "demo-nginx",
            "category": "application", "event_type": "http_request", "host": "web-01", "service": "checkout",
            "message": f"POST /checkout returned {status}", "attributes": {"status_code": status}})
    for index in range(3):
        raw.append({"timestamp": start + timedelta(seconds=index), "source": "demo-app",
            "category": "application", "event_type": "exception", "host": "api-01", "service": "orders",
            "message": "Timeout acquiring connection from database pool", "attributes": {}})
    return [TelemetryEvent.model_validate(item) for item in raw]
