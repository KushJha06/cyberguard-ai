from fastapi.testclient import TestClient

from cyberguard.api.app import app


def test_capability_and_dataset_endpoints():
    client = TestClient(app)
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["rules"] == 12
    assert health.headers["X-Request-ID"]
    assert len(client.get("/api/v1/rules").json()) == 12
    assert len(client.get("/api/v1/datasets").json()) >= 5
    plugins = client.get("/api/v1/plugins")
    assert plugins.status_code == 200
    assert len(plugins.json()) >= 18
    assert client.get("/api/v1/plugin-api-version").json() == {"version": "1"}


def test_agent_heartbeat_registers_live_system():
    client = TestClient(app)
    response = client.post(
        "/api/v1/agents/heartbeat",
        json={
            "agent_id": "test-agent",
            "hostname": "test-host",
            "platform": "Linux test",
            "events": [
                {
                    "source": "cyberguard-agent",
                    "category": "system",
                    "event_type": "memory_usage",
                    "host": "test-host",
                    "message": "sample",
                    "attributes": {"memory_used_percent": 50},
                }
            ],
        },
    )
    assert response.status_code == 200
    agents = client.get("/api/v1/agents").json()
    assert any(agent["agent_id"] == "test-agent" for agent in agents)


def test_unknown_text_file_gets_safe_universal_analysis():
    client = TestClient(app)
    response = client.post(
        "/api/v1/ingest/file",
        files={
            "file": (
                "service.trace",
                b"ERROR dependency timeout while starting application",
                "text/plain",
            )
        },
    )
    assert response.status_code == 200
    assert response.json()["accepted_events"] == 1
    assert response.json()["diagnosis"]["readiness"] == "review"
    assert response.json()["incidents"][0]["rule_ids"] == ["CG-APP-003"]
    assert response.json()["manifest"]["uploaded_file"] == "service.trace"
    assert response.json()["manifest"]["files_analyzed"] == ["service.trace"]
    assert response.json()["manifest"]["rules_evaluated"] == 12


def test_complete_demo_exercises_every_rule():
    client = TestClient(app)
    response = client.post("/api/v1/demo/load")
    assert response.status_code == 200
    assert len(response.json()["incidents"]) == 9
    assert {rule for item in response.json()["incidents"] for rule in item["rule_ids"]} == {
        "CG-APP-001",
        "CG-APP-002",
        "CG-CFG-001",
        "CG-FIM-001",
        "CG-SEC-001",
        "CG-SEC-002",
        "CG-SYS-001",
        "CG-SYS-002",
        "CG-SYS-003",
    }


def test_dry_run_does_not_require_persistence():
    client = TestClient(app)
    response = client.post(
        "/api/v1/ingest/events?persist=false",
        json={
            "events": [
                {
                    "source": "test",
                    "category": "system",
                    "event_type": "disk_usage",
                    "host": "db-1",
                    "message": "disk high",
                    "attributes": {"disk_used_percent": 96, "mount": "/"},
                }
            ]
        },
    )
    assert response.status_code == 200
    assert response.json()["incidents"][0]["rule_ids"] == ["CG-SYS-001"]
    assert response.json()["processing_ms"] >= 0
