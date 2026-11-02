import argparse
import os
import platform
import socket
import time
from pathlib import Path
from uuid import NAMESPACE_DNS, uuid5

import httpx

from .collector import SystemCollector
from .models import AgentHeartbeat


def _csv_env(name: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, "").split(",") if item.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only CyberGuard host monitoring agent")
    parser.add_argument(
        "--api-url", default=os.getenv("CYBERGUARD_API_URL", "http://localhost:8000")
    )
    parser.add_argument(
        "--interval", type=int, default=int(os.getenv("CYBERGUARD_AGENT_INTERVAL", "30"))
    )
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--agent-id", default=os.getenv("CYBERGUARD_AGENT_ID"))
    args = parser.parse_args()
    hostname = socket.gethostname()
    agent_id = args.agent_id or str(uuid5(NAMESPACE_DNS, hostname))
    collector = SystemCollector(
        hostname=hostname,
        services=_csv_env("CYBERGUARD_AGENT_SERVICES"),
        health_urls=_csv_env("CYBERGUARD_AGENT_HEALTH_URLS"),
        log_paths=[Path(item) for item in _csv_env("CYBERGUARD_AGENT_LOG_PATHS")],
        watch_paths=[Path(item) for item in _csv_env("CYBERGUARD_AGENT_WATCH_PATHS")],
    )
    headers = {}
    if token := os.getenv("CYBERGUARD_AGENT_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    while True:
        heartbeat = AgentHeartbeat(
            agent_id=agent_id,
            hostname=hostname,
            platform=f"{platform.system()} {platform.release()}",
            events=collector.collect(),
        )
        try:
            response = httpx.post(
                f"{args.api_url.rstrip('/')}/api/v1/agents/heartbeat",
                json=heartbeat.model_dump(mode="json"),
                headers=headers,
                timeout=30,
            )
            response.raise_for_status()
            result = response.json()
            print(
                f"sent={len(heartbeat.events)} incidents={len(result['incidents'])} processing_ms={result['processing_ms']}"
            )
        except httpx.HTTPError as exc:
            print(f"heartbeat failed: {exc}")
        if args.once:
            break
        time.sleep(max(args.interval, 5))


if __name__ == "__main__":
    main()
