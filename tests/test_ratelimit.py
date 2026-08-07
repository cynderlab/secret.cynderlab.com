from fastapi.testclient import TestClient

from app.main import create_app
from app.ratelimit import RateLimiter
from conftest import make_settings  # pytest puts tests/ on sys.path (no __init__.py needed)


def test_limiter_sliding_window():
    rl = RateLimiter(limit=2, window_seconds=3600)
    assert rl.check("1.2.3.4", now=1000.0) is None
    assert rl.check("1.2.3.4", now=1001.0) is None
    retry = rl.check("1.2.3.4", now=1002.0)
    assert isinstance(retry, int) and retry > 0
    assert rl.check("5.6.7.8", now=1002.0) is None          # other ip unaffected
    assert rl.check("1.2.3.4", now=1000.0 + 3601) is None    # window slid


def test_create_endpoints_return_429(tmp_path):
    app = create_app(make_settings(tmp_path, rate_limit_per_hour=2))
    with TestClient(app) as client:
        assert client.post("/api/secrets", json={"secret": "a"}).status_code == 201
        assert client.post("/api/secrets", json={"secret": "b"}).status_code == 201
        r = client.post("/api/secrets", json={"secret": "c"})
        assert r.status_code == 429
        assert "retry-after" in {k.lower() for k in r.headers}
        # reads are not rate limited
        assert client.get("/api/secrets/" + "x" * 22).status_code == 404
