from app.config import load_settings


def test_defaults(monkeypatch):
    for var in ("SECRET_DB_PATH", "SECRET_BASE_URL", "SECRET_MAX_BYTES",
                "SECRET_MAX_TTL_DAYS", "SECRET_RATE_LIMIT_PER_HOUR"):
        monkeypatch.delenv(var, raising=False)
    s = load_settings()
    assert s.db_path == "data/secrets.db"
    assert s.base_url == "http://127.0.0.1:8321"
    assert s.max_secret_bytes == 262144
    assert s.max_ttl_days == 30
    assert s.rate_limit_per_hour == 20


def test_env_overrides_and_trailing_slash(monkeypatch):
    monkeypatch.setenv("SECRET_DB_PATH", "/tmp/x.db")
    monkeypatch.setenv("SECRET_BASE_URL", "https://secret.cynderlab.com/")
    monkeypatch.setenv("SECRET_MAX_BYTES", "1024")
    s = load_settings()
    assert s.db_path == "/tmp/x.db"
    assert s.base_url == "https://secret.cynderlab.com"  # no trailing slash
    assert s.max_secret_bytes == 1024
