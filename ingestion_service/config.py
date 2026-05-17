"""Configuration for the ingestion service."""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class IngestionSettings(BaseSettings):
    """Runtime configuration loaded from environment variables."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    opensearch_host: str = "wazuh.indexer"
    opensearch_port: int = 9200
    opensearch_username: str = "admin"
    opensearch_password: str = "admin"
    opensearch_index_pattern: str = "wazuh-alerts-*"

    poll_interval_seconds: int = 5
    batch_size: int = 200
    request_timeout_seconds: int = 30
    retry_backoff_seconds: int = 5
    max_retries: int = 12

    checkpoint_path: Path = Field(default_factory=lambda: Path(__file__).resolve().parent / "state" / "checkpoint.json")
    output_path: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parent / "logs" / "normalized_events.ndjson"
    )


settings = IngestionSettings()
