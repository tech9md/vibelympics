"""Application configuration."""
from pydantic import ConfigDict, field_validator
from pydantic_settings import BaseSettings
from typing import Optional
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # App settings
    app_name: str = "PyShield"
    app_version: str = "1.0.0"
    debug: bool = False

    # API URLs
    pypi_api_url: str = "https://pypi.org/pypi"
    osv_api_url: str = "https://api.osv.dev/v1"

    # GitHub (optional)
    github_token: Optional[str] = None
    github_api_url: str = "https://api.github.com"

    # Database
    database_url: str = "sqlite+aiosqlite:///./pyshield.db"

    # Cache settings
    cache_ttl_seconds: int = 3600  # 1 hour

    # Package analysis
    max_package_size_mb: int = 50
    temp_dir: str = "/tmp/pyshield"

    # Logging settings
    log_level: str = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    log_file: str = "pyshield.log"
    log_max_bytes: int = 10 * 1024 * 1024  # 10MB
    log_backup_count: int = 5

    # CORS settings (security)
    # In development: use ["http://localhost:5173", "http://localhost:3000"]
    # In production: use specific domain(s) like ["https://your-domain.com"]
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]
    cors_allow_credentials: bool = True
    cors_allow_methods: list[str] = ["GET", "POST", "PUT", "DELETE"]
    cors_allow_headers: list[str] = ["Content-Type", "Authorization", "X-Request-ID"]

    @field_validator("cors_origins", "cors_allow_methods", "cors_allow_headers", mode="before")
    @classmethod
    def split_comma_separated(cls, v):
        """Parse comma-separated string from env var into list."""
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8"
    )


settings = Settings()
