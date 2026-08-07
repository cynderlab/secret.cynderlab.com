from datetime import timedelta

from app import cleanup, store
from app.db import connect, migrate


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
