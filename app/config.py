import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    db_path: str
    base_url: str
    max_secret_bytes: int
    max_ttl_days: int
    rate_limit_per_hour: int


def load_settings() -> Settings:
    return Settings(
        db_path=os.environ.get("SECRET_DB_PATH", "data/secrets.db"),
        base_url=os.environ.get("SECRET_BASE_URL", "http://127.0.0.1:8321").rstrip("/"),
        max_secret_bytes=int(os.environ.get("SECRET_MAX_BYTES", "262144")),
        max_ttl_days=int(os.environ.get("SECRET_MAX_TTL_DAYS", "30")),
        rate_limit_per_hour=int(os.environ.get("SECRET_RATE_LIMIT_PER_HOUR", "20")),
    )
