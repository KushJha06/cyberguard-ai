import pytest

from cyberguard.analysis.diagnostics import diagnose
from cyberguard.core.models import TelemetryEvent
from cyberguard.ingestion.universal_adapter import UniversalTextAdapter


def test_universal_adapter_classifies_unknown_log_extension(tmp_path):
    path = tmp_path / "application.custom"
    path.write_text("2026-10-02T10:00:00Z ERROR request failed with timeout\n", encoding="utf-8")
    events = UniversalTextAdapter().parse(path)
    assert events[0].event_type == "log_line"
    summary = diagnose(events, [])
    assert summary.readiness == "review"
    assert summary.primary_issue_area == "logs_or_telemetry"


def test_universal_adapter_rejects_binary_file(tmp_path):
    path = tmp_path / "capture.bin"
    path.write_bytes(b"\x00\x01\x02\xff" * 100)
    with pytest.raises(ValueError, match="binary"):
        UniversalTextAdapter().parse(path)


def test_diagnosis_identifies_application_issue():
    event = TelemetryEvent(source="test", category="application", message="application exception")
    summary = diagnose([event], [])
    assert summary.primary_issue_area == "application"
    assert summary.readiness == "review"
