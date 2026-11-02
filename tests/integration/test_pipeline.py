import json

from cyberguard.core.service import TriageService
from cyberguard.storage.sqlite import SQLiteStore


def test_json_to_incident(tmp_path):
    telemetry = tmp_path / "events.json"
    telemetry.write_text(
        json.dumps(
            [
                {
                    "source": "node-exporter",
                    "category": "system",
                    "event_type": "disk_usage",
                    "host": "web-1",
                    "message": "Root filesystem almost full",
                    "attributes": {"disk_used_percent": 97, "mount": "/"},
                }
            ]
        )
    )
    service = TriageService(SQLiteStore(tmp_path / "test.db"))
    events, incidents = service.ingest_file(telemetry, "json")
    assert len(events) == 1
    assert incidents[0].title == "Disk-space exhaustion"
    assert service.store.event_count() == 1


def test_repeated_telemetry_updates_correlated_incident(tmp_path):
    telemetry = tmp_path / "events.json"
    telemetry.write_text(
        json.dumps(
            [
                {
                    "source": "agent",
                    "category": "system",
                    "event_type": "disk_usage",
                    "host": "db-1",
                    "message": "disk high",
                    "attributes": {"disk_used_percent": 96, "mount": "/data"},
                }
            ]
        )
    )
    service = TriageService(SQLiteStore(tmp_path / "dedup.db"))
    first = service.ingest_file(telemetry, "json")[1][0]
    second = service.ingest_file(telemetry, "json")[1][0]
    assert first.id == second.id
    assert service.store.incident_count() == 1
