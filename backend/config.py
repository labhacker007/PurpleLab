"""Application configuration via pydantic-settings.

All settings can be overridden via environment variables or a .env file.
"""
from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """PurpleLab application settings."""

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://purplelab:purplelab@localhost:5432/purplelab"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # LLM
    ANTHROPIC_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    DEFAULT_MODEL: str = "claude-sonnet-4-20250514"

    # App
    APP_NAME: str = "PurpleLab"
    DEBUG: bool = False
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:4000"]

    # Encryption
    ENCRYPTION_KEY: str = ""  # Fernet key for SIEM credentials

    # Celery
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    # Vector DB
    CHROMA_PERSIST_DIR: str = "./data/chroma"

    # Joti integration
    JOTI_BASE_URL: str = ""              # e.g. "https://joti.yourorg.com"
    JOTI_API_KEY: str = ""               # "joti_<64 hex chars>"
    JOTI_WEBHOOK_TOKEN: str = ""         # For alert ingestion endpoint

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
