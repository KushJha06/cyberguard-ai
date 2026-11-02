import hashlib
import os
import platform
import re
import shutil
import socket
import subprocess  # nosec B404
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic

import httpx
import psutil

from cyberguard.core.enums import EventCategory
from cyberguard.core.models import TelemetryEvent
from cyberguard.ingestion.config_file_adapter import SSHConfigAdapter
from cyberguard.ingestion.universal_adapter import UniversalTextAdapter


class SystemCollector:
    """Read-only, cross-platform host telemetry collector with small local state."""

    def __init__(
        self,
        hostname: str | None = None,
        services: list[str] | None = None,
        health_urls: list[str] | None = None,
        log_paths: list[Path] | None = None,
        watch_paths: list[Path] | None = None,
    ) -> None:
        self.hostname = hostname or socket.gethostname()
        self.services = services or []
        self.health_urls = health_urls or []
        self.log_paths = log_paths or []
        self.watch_paths = watch_paths or []
        self._disk_history: dict[str, tuple[float, float]] = {}
        self._log_offsets: dict[Path, int] = {}
        self._hashes: dict[Path, str] = {}

    def collect(self) -> list[TelemetryEvent]:
        events = [self._memory_event(), self._host_event()]
        events.extend(self._disk_events())
        events.extend(self._service_events())
        events.extend(self._health_events())
        events.extend(self._tail_logs())
        events.extend(self._file_integrity_events())
        events.extend(self._ssh_configuration_events())
        return events

    def _memory_event(self) -> TelemetryEvent:
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        return self._event(
            EventCategory.SYSTEM,
            "memory_usage",
            "Memory utilization sample",
            {
                "memory_used_percent": memory.percent,
                "available_bytes": memory.available,
                "swap_used_percent": swap.percent,
            },
        )

    def _host_event(self) -> TelemetryEvent:
        load = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)
        return self._event(
            EventCategory.SYSTEM,
            "host_health",
            "Host health sample",
            {
                "cpu_used_percent": psutil.cpu_percent(interval=0.1),
                "load_1m": load[0],
                "boot_time": datetime.fromtimestamp(psutil.boot_time(), UTC).isoformat(),
                "process_count": len(psutil.pids()),
            },
        )

    def _disk_events(self) -> list[TelemetryEvent]:
        events, seen = [], set()
        now = monotonic()
        for partition in psutil.disk_partitions(all=False):
            if partition.mountpoint in seen:
                continue
            seen.add(partition.mountpoint)
            try:
                usage = psutil.disk_usage(partition.mountpoint)
            except (PermissionError, OSError):
                continue
            attributes = {
                "disk_used_percent": usage.percent,
                "mount": partition.mountpoint,
                "free_bytes": usage.free,
                "filesystem": partition.fstype,
            }
            previous = self._disk_history.get(partition.mountpoint)
            if previous and now > previous[0] and usage.percent > previous[1]:
                percent_per_hour = (usage.percent - previous[1]) / ((now - previous[0]) / 3600)
                if percent_per_hour > 0:
                    attributes["growth_percent_per_hour"] = round(percent_per_hour, 3)
                    attributes["projected_minutes_to_full"] = round(
                        (100 - usage.percent) / percent_per_hour * 60, 1
                    )
            self._disk_history[partition.mountpoint] = (now, usage.percent)
            events.append(
                self._event(
                    EventCategory.SYSTEM,
                    "disk_usage",
                    f"Disk utilization sample for {partition.mountpoint}",
                    attributes,
                )
            )
        return events

    def _service_events(self) -> list[TelemetryEvent]:
        events = []
        for service in self.services:
            state = self._service_state(service)
            events.append(
                self._event(
                    EventCategory.SYSTEM,
                    "service_status",
                    f"Service {service} is {state}",
                    {"service_state": state},
                    service=service,
                )
            )
        return events

    @staticmethod
    def _service_state(service: str) -> str:
        if platform.system() == "Windows":
            try:
                return (
                    "running" if psutil.win_service_get(service).status() == "running" else "down"
                )
            except (psutil.Error, AttributeError):
                return "unknown"
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@:-]*", service):
            return "unknown"
        systemctl = shutil.which("systemctl")
        if systemctl is None:
            return "unknown"
        try:
            # The service is validated above and the argument list avoids shell parsing.
            result = subprocess.run(  # nosec B603
                [systemctl, "is-active", service],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            return (
                "running"
                if result.stdout.strip() == "active"
                else result.stdout.strip() or "unknown"
            )
        except (OSError, subprocess.TimeoutExpired):
            return "unknown"

    def _health_events(self) -> list[TelemetryEvent]:
        events = []
        for url in self.health_urls:
            service = url.split("//")[-1].split("/")[0]
            try:
                response = httpx.get(url, timeout=5)
                state = "running" if response.status_code < 500 else "failed"
                detail = {
                    "service_state": state,
                    "url": url,
                    "status_code": response.status_code,
                    "latency_ms": response.elapsed.total_seconds() * 1000,
                }
            except httpx.HTTPError as exc:
                state, detail = "down", {"service_state": "down", "url": url, "error": str(exc)}
            events.append(
                self._event(
                    EventCategory.SYSTEM,
                    "service_status",
                    f"Application health endpoint {url} is {state}",
                    detail,
                    service=service,
                )
            )
        return events

    def _tail_logs(self) -> list[TelemetryEvent]:
        events = []
        for path in self.log_paths:
            try:
                size = path.stat().st_size
                offset = self._log_offsets.get(path, max(0, size - 64_000))
                if size < offset:
                    offset = 0
                with path.open("r", encoding="utf-8", errors="replace") as handle:
                    handle.seek(offset)
                    lines = handle.readlines(256_000)
                    self._log_offsets[path] = handle.tell()
            except OSError:
                continue
            for number, line in enumerate(lines, 1):
                message = line.strip()
                if not message:
                    continue
                category, event_type = UniversalTextAdapter._classify_line(message)
                events.append(
                    self._event(
                        category, event_type, message, {"path": str(path), "batch_line": number}
                    )
                )
        return events

    def _file_integrity_events(self) -> list[TelemetryEvent]:
        events = []
        for path in self.watch_paths:
            if not path.is_file():
                continue
            try:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                continue
            previous = self._hashes.get(path)
            self._hashes[path] = digest
            if previous and previous != digest:
                events.append(
                    self._event(
                        EventCategory.FILE_INTEGRITY,
                        "file_change",
                        f"Watched file changed: {path}",
                        {
                            "path": str(path),
                            "action": "modified",
                            "sha256": digest,
                            "previous_sha256": previous,
                        },
                    )
                )
        return events

    def _ssh_configuration_events(self) -> list[TelemetryEvent]:
        if platform.system() == "Windows":
            candidates = [Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "ssh/sshd_config"]
        else:
            candidates = [Path("/etc/ssh/sshd_config")]
        for path in candidates:
            if path.is_file():
                try:
                    event = SSHConfigAdapter().parse(path)[0]
                    event.host = self.hostname
                    return [event]
                except OSError:
                    pass
        return []

    def _event(
        self,
        category: EventCategory,
        event_type: str,
        message: str,
        attributes: dict,
        service: str | None = None,
    ) -> TelemetryEvent:
        return TelemetryEvent(
            source="cyberguard-agent",
            category=category,
            event_type=event_type,
            host=self.hostname,
            service=service,
            message=message,
            attributes=attributes,
        )
