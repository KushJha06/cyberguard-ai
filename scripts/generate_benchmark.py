#!/usr/bin/env python3
"""Generate deterministic, shareable CyberGuard benchmark telemetry."""
import argparse
import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path


def generate(seed: int = 42) -> list[dict]:
    rng = random.Random(seed)
    start = datetime(2026, 1, 1, tzinfo=UTC)
    events = []
    for index in range(250):
        status = 500 if 100 <= index < 125 else rng.choice([200, 200, 200, 201, 204])
        events.append({"timestamp": (start + timedelta(seconds=index * 3)).isoformat(), "source": "benchmark",
            "category": "application", "event_type": "http_request", "host": "web-01", "service": "checkout",
            "message": f"HTTP request completed with {status}", "attributes": {"status_code": status, "route": "/checkout"}})
    for index in range(8):
        events.append({"timestamp": (start + timedelta(minutes=20, seconds=index * 20)).isoformat(),
            "source": "benchmark", "category": "authentication", "event_type": "login", "host": "bastion-01",
            "service": "ssh", "message": "Failed password for invalid user",
            "attributes": {"source_ip": "203.0.113.42", "outcome": "failure"}})
    events.append({"timestamp": (start + timedelta(minutes=30)).isoformat(), "source": "benchmark",
        "category": "system", "event_type": "disk_usage", "host": "db-01", "message": "Disk utilization high",
        "attributes": {"disk_used_percent": 96.2, "mount": "/var/lib/postgresql"}})
    return events


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("data/samples/benchmark.json"))
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = generate(args.seed)
    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Wrote {len(payload)} events to {args.output}")


if __name__ == "__main__":
    main()
