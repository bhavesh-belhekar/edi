import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

class SystemConfig(BaseSettings):
    """
    CENTRALIZED CONFIGURATION MODULE.
    Manages all environment variables and secrets via Pydantic settings.
    Ensures type safety and prevents missing configurations at startup.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Global System Settings
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"

    # OpenSearch Settings
    OPENSEARCH_HOST: str = "localhost"
    OPENSEARCH_PORT: int = 9200
    OPENSEARCH_USER: str = "admin"
    OPENSEARCH_PASSWORD: str = "admin"
    OPENSEARCH_API_URL: str = "https://localhost:9200"

    # PostgreSQL Settings
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "cyber_soc"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    
    @property
    def postgres_uri(self) -> str:
        return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

    # RabbitMQ Settings
    RABBITMQ_HOST: str = "localhost"
    RABBITMQ_PORT: int = 5672
    RABBITMQ_USER: str = "guest"
    RABBITMQ_PASSWORD: str = "guest"
    
    @property
    def rabbitmq_uri(self) -> str:
        return f"amqp://{self.RABBITMQ_USER}:{self.RABBITMQ_PASSWORD}@{self.RABBITMQ_HOST}:{self.RABBITMQ_PORT}/"

    # Queue Names
    QUEUE_NEW_ALERTS: str = "queue.alerts.new"
    QUEUE_ML_PROCESSING: str = "queue.ml.processing"
    QUEUE_GRAPH_CORRELATION: str = "queue.graph.correlation"

    # Ollama Local LLM Settings
    OLLAMA_HOST: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3"

    # Fidelity Engine Thresholds
    ANOMALY_THRESHOLD: float = 0.85
    UEBA_THRESHOLD: float = 0.80

# Instantiate a single global config object to be imported by all modules
settings = SystemConfig()
