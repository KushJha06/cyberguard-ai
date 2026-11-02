from cyberguard.core.enums import EventCategory
from cyberguard.core.models import TelemetryEvent
from cyberguard.detection.file_integrity.sensitive_file_change import SensitiveFileChangeRule
from cyberguard.detection.security.suspicious_powershell import SuspiciousPowerShellRule
from cyberguard.detection.system.capacity_forecast import CapacityForecastRule
from cyberguard.detection.system.memory_pressure import MemoryPressureRule
from cyberguard.detection.system.service_down import ServiceDownRule


def event(**values):
    base = {"source": "test", "message": "test", "attributes": {}}
    base.update(values)
    return TelemetryEvent(**base)


def test_capacity_forecast_warns_before_static_threshold():
    finding = CapacityForecastRule().evaluate(
        [
            event(
                host="db-1",
                attributes={
                    "disk_used_percent": 82,
                    "mount": "/data",
                    "projected_minutes_to_full": 90,
                    "growth_percent_per_hour": 12,
                },
            )
        ]
    )
    assert finding[0].rule_id == "CG-SYS-004"


def test_memory_pressure():
    finding = MemoryPressureRule().evaluate(
        [event(host="db-1", attributes={"memory_used_percent": 97})]
    )
    assert finding[0].rule_id == "CG-SYS-002"


def test_service_down():
    finding = ServiceDownRule().evaluate(
        [
            event(
                event_type="service_status",
                host="web-1",
                service="nginx",
                attributes={"service_state": "failed"},
            )
        ]
    )
    assert finding[0].severity == "high"


def test_sensitive_file_change():
    finding = SensitiveFileChangeRule().evaluate(
        [
            event(
                category=EventCategory.FILE_INTEGRITY,
                host="web-1",
                attributes={"path": "/etc/passwd", "action": "modified"},
            )
        ]
    )
    assert finding[0].mitre_techniques == ["T1565.001"]


def test_suspicious_powershell():
    finding = SuspiciousPowerShellRule().evaluate(
        [event(host="win-1", attributes={"command_line": "powershell -EncodedCommand AAAA"})]
    )
    assert finding[0].rule_id == "CG-SEC-002"
