import os
from typing import Any

import httpx


class CyberGuardClient:
    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = (
            base_url or os.getenv("CYBERGUARD_API_URL", "http://localhost:8000")
        ).rstrip("/")

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        response = httpx.request(method, f"{self.base_url}{path}", timeout=30, **kwargs)
        response.raise_for_status()
        return response.json()

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/health")

    def incidents(self, limit: int = 250) -> list[dict[str, Any]]:
        return self._request("GET", f"/api/v1/incidents?limit={limit}")

    def incident(self, incident_id: str) -> dict[str, Any]:
        return self._request("GET", f"/api/v1/incidents/{incident_id}")

    def upload(
        self, name: str, content: bytes, content_type: str, adapter: str | None = None
    ) -> dict[str, Any]:
        data = {"adapter": adapter} if adapter else {}
        return self._request(
            "POST", "/api/v1/ingest/file", data=data, files={"file": (name, content, content_type)}
        )

    def load_demo(self) -> dict[str, Any]:
        return self._request("POST", "/api/v1/demo/load")

    def agents(self) -> list[dict[str, Any]]:
        return self._request("GET", "/api/v1/agents")

    def preflight(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/preflight")

    def stats(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/stats")

    def rules(self) -> list[dict[str, str]]:
        return self._request("GET", "/api/v1/rules")

    def datasets(self) -> list[dict[str, Any]]:
        return self._request("GET", "/api/v1/datasets")

    def plugins(self) -> list[dict[str, Any]]:
        return self._request("GET", "/api/v1/plugins")

    def update_status(self, incident_id: str, status: str) -> dict[str, Any]:
        return self._request(
            "PATCH", f"/api/v1/incidents/{incident_id}/status", json={"status": status}
        )
