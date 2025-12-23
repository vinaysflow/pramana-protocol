from __future__ import annotations

import os

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Load .env from either backend/ or repo root
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))


def _default_database_url() -> str:
    # Prefer explicit env
    if os.getenv("DATABASE_URL"):
        return os.getenv("DATABASE_URL")  # type: ignore

    # Hugging Face Spaces: prefer persistent SQLite
    if os.getenv("SPACE_ID") or os.getenv("HF_SPACE") or os.getenv("HF_HOME"):
        return "sqlite:////data/pramana.db"

    # Local dev default (docker-compose)
    return "postgresql://pramana:pramana_dev_password@localhost:5432/pramana"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    database_url: str = Field(default_factory=_default_database_url, validation_alias="DATABASE_URL")

    api_secret_key: str = Field(default="change-me", validation_alias="API_SECRET_KEY")
    api_host: str = Field(default="0.0.0.0", validation_alias="API_HOST")
    api_port: int = Field(default=8000, validation_alias="API_PORT")

    # did:web method expects percent-encoding for ':' in ports (e.g. localhost%3A8000)
    pramana_domain: str = Field(default="localhost%3A8000", validation_alias="PRAMANA_DOMAIN")
    pramana_scheme: str = Field(default="http", validation_alias="PRAMANA_SCHEME")

    allowed_origins_raw: str = Field(
        default="http://127.0.0.1:6080,http://localhost:6080,http://127.0.0.1:8000,http://localhost:8000",
        validation_alias="ALLOWED_ORIGINS",
    )
    cors_enabled: bool = Field(default=True, validation_alias="CORS_ENABLED")

    debug: bool = Field(default=True, validation_alias="DEBUG")
    env: str = Field(default="dev", validation_alias="ENV")
    migrations_strict: bool = Field(default=False, validation_alias="MIGRATIONS_STRICT")
    log_level: str = Field(default="INFO", validation_alias="LOG_LEVEL")

    # Auth (JWT bearer stub)
    auth_mode: str = Field(default="hs256", validation_alias="AUTH_MODE")
    oidc_issuer: str = Field(default="", validation_alias="OIDC_ISSUER")
    oidc_audience: str = Field(default="", validation_alias="OIDC_AUDIENCE")
    oidc_jwks_url: str = Field(default="", validation_alias="OIDC_JWKS_URL")
    oidc_jwks_json: str = Field(default="", validation_alias="OIDC_JWKS_JSON")
    oidc_client_id: str = Field(default="", validation_alias="OIDC_CLIENT_ID")
    auth_jwt_secret: str = Field(default="dev-secret-change", validation_alias="AUTH_JWT_SECRET")
    auth_jwt_issuer: str = Field(default="pramana", validation_alias="AUTH_JWT_ISSUER")
    pramana_dev_mode: bool = Field(default=False, validation_alias="PRAMANA_DEV_MODE")

    # Spaces demo mode (per-session demo tokens -> isolated tenants)
    demo_mode: bool = Field(default=bool(os.getenv("SPACE_ID") or os.getenv("HF_SPACE") or os.getenv("HF_HOME")), validation_alias="DEMO_MODE")
    demo_jwt_secret: str = Field(default="demo-secret-change", validation_alias="DEMO_JWT_SECRET")
    demo_token_ttl_seconds: int = Field(default=3600, validation_alias="DEMO_TOKEN_TTL_SECONDS")

    max_body_bytes: int = Field(default=1_000_000, validation_alias="MAX_BODY_BYTES")
    rate_limit_enabled: bool = Field(default=False, validation_alias="RATE_LIMIT_ENABLED")
    rate_limit_per_minute: int = Field(default=120, validation_alias="RATE_LIMIT_PER_MINUTE")

    @property
    def allowed_origins(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins_raw.split(",") if o.strip()]


settings = Settings()
