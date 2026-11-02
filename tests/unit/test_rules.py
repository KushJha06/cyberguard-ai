from datetime import UTC, datetime, timedelta

from cyberguard.core.enums import EventCategory
from cyberguard.core.models import TelemetryEvent
from cyberguard.detection.application.database_pool import DatabasePoolRule
from cyberguard.detection.application.http_error_spike import HTTPErrorSpikeRule
from cyberguard.detection.configuration.insecure_ssh import InsecureSSHRule
from cyberguard.detection.security.brute_force import SSHBruteForceRule
from cyberguard.detection.system.disk_full import DiskFullRule


def event(**overrides):
    values = dict(source="test", category=EventCategory.SYSTEM, message="test", attributes={})
    values.update(overrides)
    return TelemetryEvent(**values)


def test_disk_full():
    findings = DiskFullRule().evaluate([event(host="db-1", attributes={"disk_used_percent": 96, "mount": "/var"})])
    assert findings[0].rule_id == "CG-SYS-001"
    assert findings[0].severity == "high"


def test_ssh_brute_force():
    now = datetime.now(UTC)
    events = [event(timestamp=now + timedelta(seconds=i), category=EventCategory.AUTHENTICATION,
        message="Failed password", host="server", attributes={"source_ip": "203.0.113.5", "outcome": "failure"}) for i in range(5)]
    assert len(SSHBruteForceRule().evaluate(events)) == 1


def test_http_spike():
    events = [event(category=EventCategory.APPLICATION, event_type="http_request", service="api",
        attributes={"status_code": 500 if i < 5 else 200}) for i in range(10)]
    assert len(HTTPErrorSpikeRule().evaluate(events)) == 1


def test_database_pool():
    events = [event(category=EventCategory.APPLICATION, message="Timeout acquiring connection", service="api") for _ in range(3)]
    assert len(DatabasePoolRule().evaluate(events)) == 1


def test_insecure_ssh():
    snapshot = event(category=EventCategory.CONFIGURATION, event_type="ssh_config_snapshot",
        attributes={"directives": {"PermitRootLogin": "yes", "PasswordAuthentication": "yes"}})
    finding = InsecureSSHRule().evaluate([snapshot])[0]
    assert "Root login" in finding.summary
