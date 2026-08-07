import sqlite3
from datetime import timedelta

import pytest

from app import store
from app.db import connect, migrate


@pytest.fixture
def conn(tmp_path):
    c = connect(str(tmp_path / "t.db"))
    migrate(c)
    return c


def future(hours=1):
    return store.iso(store.utcnow() + timedelta(hours=hours))


def past(hours=1):
    return store.iso(store.utcnow() - timedelta(hours=hours))


SLUG = "AAAAAAAAAAAAAAAAAAAAAA"


def test_create_and_consume_once(conn):
    store.create_secret(conn, SLUG, b"ct", b"nonce123", False, future())
    row = store.consume_secret(conn, SLUG)
    assert row["ciphertext"] == b"ct"
    assert row["nonce"] == b"nonce123"
    assert row["has_passphrase"] == 0
    assert store.consume_secret(conn, SLUG) is None       # burned: second read fails
    assert store.get_meta(conn, SLUG) is None


def test_expired_secret_is_never_served(conn):
    store.create_secret(conn, SLUG, b"ct", b"n", False, past())
    assert store.get_meta(conn, SLUG) is None
    assert store.consume_secret(conn, SLUG) is None
    assert conn.execute("SELECT COUNT(*) FROM secrets").fetchone()[0] == 0  # gone


def test_meta_does_not_burn(conn):
    store.create_secret(conn, SLUG, b"ct", b"n", True, future())
    assert store.get_meta(conn, SLUG)["has_passphrase"] == 1
    assert store.get_meta(conn, SLUG) is not None          # still there


def test_duplicate_slug_raises(conn):
    store.create_secret(conn, SLUG, b"a", b"n", False, future())
    with pytest.raises(sqlite3.IntegrityError):
        store.create_secret(conn, SLUG, b"b", b"n", False, future())


def test_purge_expired(conn):
    store.create_secret(conn, "A" * 22, b"a", b"n", False, past())
    store.create_secret(conn, "B" * 22, b"b", b"n", False, future())
    assert store.purge_expired(conn) == 1
    assert conn.execute("SELECT slug FROM secrets").fetchone()["slug"] == "B" * 22


def test_get_auth_and_register_failure(conn):
    store.create_secret(conn, SLUG, b"ct", b"n", True, future(), verifier_hash=b"h" * 32)
    auth = store.get_auth(conn, SLUG)
    assert auth["verifier_hash"] == b"h" * 32
    assert auth["failed_attempts"] == 0
    assert auth["locked_until"] is None

    for expected_left in (4, 3, 2, 1):
        assert store.register_failure(conn, SLUG) == expected_left
    assert store.register_failure(conn, SLUG) == "locked"     # 5th failure locks

    auth = store.get_auth(conn, SLUG)
    assert auth["failed_attempts"] == 0                       # counter reset on lock
    assert auth["locked_until"] > store.iso(store.utcnow())   # ~5 min ahead
    # secret was NOT burned by failures
    assert store.get_meta(conn, SLUG) is not None


def test_get_auth_none_for_missing_or_expired(conn):
    assert store.get_auth(conn, SLUG) is None
    store.create_secret(conn, SLUG, b"ct", b"n", False, past())
    assert store.get_auth(conn, SLUG) is None
