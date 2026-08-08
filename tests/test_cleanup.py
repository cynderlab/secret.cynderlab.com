from datetime import timedelta

from fastapi.testclient import TestClient

from app import cleanup, store
from app.db import connect, migrate
from app.main import create_app
from conftest import make_settings


def test_run_purges_only_expired(tmp_path):
    conn = connect(str(tmp_path / "t.db"))
    migrate(conn)
    now = store.utcnow()
    store.create_secret(conn, "A" * 22, b"x", b"n", False, store.iso(now - timedelta(hours=2)))
    store.create_secret(conn, "B" * 22, b"x", b"n", False, store.iso(now - timedelta(minutes=1)))
    store.create_secret(conn, "C" * 22, b"x", b"n", False, store.iso(now + timedelta(days=1)))
    assert cleanup.run(conn) == 2
    assert conn.execute("SELECT COUNT(*) FROM secrets").fetchone()[0] == 1
    assert cleanup.run(conn) == 0


def test_lifespan_sweeps_expired_rows_on_startup(tmp_path):
    app = create_app(make_settings(tmp_path))
    past = store.iso(store.utcnow() - timedelta(hours=1))
    store.create_secret(app.state.db, "A" * 22, b"x", b"n", False, past)
    assert app.state.db.execute("SELECT COUNT(*) FROM secrets").fetchone()[0] == 1
    with TestClient(app):  # entering starts the lifespan -> initial sweep
        import time
        for _ in range(50):  # the sweep runs in a background task; give it a moment
            if app.state.db.execute("SELECT COUNT(*) FROM secrets").fetchone()[0] == 0:
                break
            time.sleep(0.1)
        assert app.state.db.execute("SELECT COUNT(*) FROM secrets").fetchone()[0] == 0
