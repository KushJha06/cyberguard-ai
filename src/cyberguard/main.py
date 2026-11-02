import argparse
from pathlib import Path

from cyberguard.core.service import TriageService


def main() -> None:
    parser = argparse.ArgumentParser(description="CyberGuard AI local triage")
    parser.add_argument("path", type=Path)
    parser.add_argument("--adapter", choices=["csv", "json", "ssh_config"])
    args = parser.parse_args()
    events, incidents = TriageService().ingest_file(args.path, args.adapter)
    print(f"Accepted {len(events)} events; created {len(incidents)} incident(s)")
    for incident in incidents:
        print(f"[{incident.severity.value.upper()}] {incident.title}: {incident.summary}")


if __name__ == "__main__":
    main()
