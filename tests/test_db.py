import sqlite3

from app.db import connect, migrate


def test_migrate_applies_once(tmp_path):
    conn = connect(str(tmp_path / "t.db"))
    assert migrate(conn) == [1]          # first run applies 001
    assert migrate(conn) == []           # second run is a no-op
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(secrets)")}
    assert cols == {"slug", "ciphertext", "nonce", "has_passphrase", "created_at", "expires_at"}


def test_connect_pragmas_and_parent_dir(tmp_path):
    conn = connect(str(tmp_path / "sub" / "dir" / "t.db"))  # parent dirs created
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert isinstance(conn.execute("SELECT 1 AS one").fetchone(), sqlite3.Row)
