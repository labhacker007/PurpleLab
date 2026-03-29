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

    # Threat Intelligence API Keys
    VIRUSTOTAL_API_KEY: str = ""         # VirusTotal API v3 key
    OTX_API_KEY: str = ""                # AlienVault OTX DirectConnect key
    # AbuseEH (URLhaus, MalwareBazaar, ThreatFox) requires no API key

    # Joti integration
    JOTI_BASE_URL: str = ""              # e.g. "https://joti.yourorg.com"
    JOTI_API_KEY: str = ""               # "joti_<64 hex chars>"
    JOTI_WEBHOOK_TOKEN: str = ""         # For alert ingestion endpoint

    # LLM Provider Keys
    GOOGLE_API_KEY: str = ""             # Google Gemini
    AZURE_OPENAI_API_KEY: str = ""       # Azure OpenAI
    AZURE_OPENAI_ENDPOINT: str = ""      # e.g. "https://myresource.openai.azure.com"
    OLLAMA_BASE_URL: str = "http://localhost:11434"  # Local Ollama instance

    # Per-function LLM model overrides (optional env-var config)
    # Format: PURPLELAB_LLM_{FUNCTION}_{FIELD}
    # e.g. PURPLELAB_LLM_LOG_GENERATION_PROVIDER=ollama
    #      PURPLELAB_LLM_LOG_GENERATION_MODEL=llama3.2

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "allow"}


settings = Settings()
