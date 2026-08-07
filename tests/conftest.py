import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def make_settings(tmp_path, **overrides) -> Settings:
    defaults = dict(
        db_path=str(tmp_path / "test.db"),
        base_url="https://secret.test",
        max_secret_bytes=262144,
        max_ttl_days=30,
        rate_limit_per_hour=1000,     # effectively off; rate-limit tests override this
    )
    defaults.update(overrides)
    return Settings(**defaults)


@pytest.fixture
def client(tmp_path):
    app = create_app(make_settings(tmp_path))
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
