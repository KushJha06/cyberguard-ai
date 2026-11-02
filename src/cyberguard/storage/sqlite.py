import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from cyberguard.agent.models import AgentHeartbeat, AgentStatus
from cyberguard.core.enums import IncidentStatus, Severity
from cyberguard.core.models import Incident, TelemetryEvent, utcnow


class SQLiteStore:
    """Small, concurrency-safe local store optimized for batch writes and paged reads."""

    def __init__(self, path: Path, busy_timeout_ms: int = 5_000) -> None:
        self.path = path
        self.busy_timeout_ms = busy_timeout_ms
        path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=self.busy_timeout_ms / 1000)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=NORMAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    severity TEXT NOT NULL, status TEXT NOT NULL, correlation_key TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_event_timestamp ON events(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_incident_created ON incidents(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_incident_correlation ON incidents(correlation_key);
                CREATE INDEX IF NOT EXISTS idx_incident_severity_status ON incidents(severity, status);
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY, hostname TEXT NOT NULL, platform TEXT NOT NULL,
                    agent_version TEXT NOT NULL, last_seen TEXT NOT NULL, event_count INTEGER NOT NULL,
                    incident_count INTEGER NOT NULL, payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_agent_last_seen ON agents(last_seen DESC);
            """)

    def save_events(self, events: list[TelemetryEvent], chunk_size: int = 1_000) -> None:
        if not events:
            return
        with self.transaction() as db:
            for start in range(0, len(events), chunk_size):
                chunk = events[start:start + chunk_size]
                db.executemany(
                    "INSERT OR REPLACE INTO events(id, timestamp, payload) VALUES (?, ?, ?)",
                    ((event.id, event.timestamp.isoformat(), event.model_dump_json()) for event in chunk),
                )

    def save_incident(self, incident: Incident) -> None:
        with self.transaction() as db:
            db.execute("""
                INSERT INTO incidents(id, created_at, updated_at, severity, status, correlation_key, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET updated_at=excluded.updated_at,
                    severity=excluded.severity, status=excluded.status, payload=excluded.payload
            """, (incident.id, incident.created_at.isoformat(), incident.updated_at.isoformat(),
                incident.severity.value, incident.status.value, incident.correlation_key,
                incident.model_dump_json()))

    def save_incidents(self, incidents: list[Incident]) -> None:
        if not incidents:
            return
        rows = [(item.id, item.created_at.isoformat(), item.updated_at.isoformat(), item.severity.value,
            item.status.value, item.correlation_key, item.model_dump_json()) for item in incidents]
        with self.transaction() as db:
            db.executemany("INSERT OR REPLACE INTO incidents VALUES (?, ?, ?, ?, ?, ?, ?)", rows)

    def list_incidents(self, limit: int = 100, offset: int = 0,
        severity: Severity | None = None, status: IncidentStatus | None = None) -> list[Incident]:
        clauses, params = [], []
        if severity:
            clauses.append("severity = ?")
            params.append(severity.value)
        if status:
            clauses.append("status = ?")
            params.append(status.value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.extend((limit, offset))
        with self.connect() as db:
            rows = db.execute(
                f"SELECT payload FROM incidents{where} ORDER BY created_at DESC LIMIT ? OFFSET ?", params
            ).fetchall()
        return [Incident.model_validate(json.loads(row["payload"])) for row in rows]

    def get_incident(self, incident_id: str) -> Incident | None:
        with self.connect() as db:
            row = db.execute("SELECT payload FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        return Incident.model_validate(json.loads(row["payload"])) if row else None

    def get_incident_by_correlation(self, correlation_key: str) -> Incident | None:
        with self.connect() as db:
            row = db.execute("SELECT payload FROM incidents WHERE correlation_key = ? "
                "ORDER BY updated_at DESC LIMIT 1", (correlation_key,)).fetchone()
        return Incident.model_validate(json.loads(row["payload"])) if row else None

    def update_incident_status(self, incident_id: str, status: IncidentStatus) -> Incident | None:
        incident = self.get_incident(incident_id)
        if not incident:
            return None
        incident.status = status
        incident.updated_at = utcnow()
        self.save_incident(incident)
        return incident

    def event_count(self) -> int:
        with self.connect() as db:
            return int(db.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def incident_count(self) -> int:
        with self.connect() as db:
            return int(db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0])

    def save_agent_heartbeat(self, heartbeat: AgentHeartbeat, incident_count: int) -> None:
        latest_metrics = {event.event_type: event.attributes for event in heartbeat.events
            if event.event_type in {"host_health", "memory_usage", "disk_usage", "service_status"}}
        payload = json.dumps(latest_metrics, default=str)
        with self.transaction() as db:
            db.execute("""
                INSERT INTO agents(agent_id, hostname, platform, agent_version, last_seen,
                    event_count, incident_count, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET hostname=excluded.hostname,
                    platform=excluded.platform, agent_version=excluded.agent_version,
                    last_seen=excluded.last_seen, event_count=excluded.event_count,
                    incident_count=excluded.incident_count, payload=excluded.payload
            """, (heartbeat.agent_id, heartbeat.hostname, heartbeat.platform,
                heartbeat.agent_version, heartbeat.timestamp.isoformat(), len(heartbeat.events),
                incident_count, payload))

    def list_agents(self, stale_seconds: int = 120) -> list[AgentStatus]:
        now = utcnow()
        with self.connect() as db:
            rows = db.execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()
        agents = []
        for row in rows:
            last_seen = datetime.fromisoformat(row["last_seen"])
            state = "online" if (now - last_seen).total_seconds() <= stale_seconds else "stale"
            agents.append(AgentStatus(agent_id=row["agent_id"], hostname=row["hostname"],
                platform=row["platform"], agent_version=row["agent_version"], last_seen=last_seen,
                state=state, event_count=row["event_count"], incident_count=row["incident_count"],
                latest_metrics=json.loads(row["payload"])))
        return agents

    def stats(self) -> dict:
        with self.connect() as db:
            events = int(db.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            incidents = int(db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0])
            severities = {row["severity"]: row["count"] for row in db.execute(
                "SELECT severity, COUNT(*) AS count FROM incidents GROUP BY severity")}
            statuses = {row["status"]: row["count"] for row in db.execute(
                "SELECT status, COUNT(*) AS count FROM incidents GROUP BY status")}
        return {"events": events, "incidents": incidents, "by_severity": severities,
            "by_status": statuses, "generated_at": datetime.now().astimezone().isoformat()}
