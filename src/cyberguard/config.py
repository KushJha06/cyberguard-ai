from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CYBERGUARD_", env_file=".env")

    database_path: Path = Path("data/runtime/cyberguard.db")
    upload_dir: Path = Path("data/uploads")
    api_url: str = "http://localhost:8000"
    redact_sensitive: bool = True
    max_upload_bytes: int = 50 * 1024 * 1024
    max_batch_events: int = 50_000
    sqlite_busy_timeout_ms: int = 5_000
    cors_origins: str = "http://localhost:8501"
    request_id_header: str = "X-Request-ID"
    agent_token: str | None = None
    agent_stale_seconds: int = 120
    enable_external_plugins: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
