import sqlite3
from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def create_secret(
    conn: sqlite3.Connection,
    slug: str,
    ciphertext: bytes,
    nonce: bytes,
    has_passphrase: bool,
    expires_at: str,
) -> None:
    conn.execute(
        "INSERT INTO secrets (slug, ciphertext, nonce, has_passphrase, created_at, expires_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (slug, ciphertext, nonce, int(has_passphrase), iso(utcnow()), expires_at),
    )
    conn.commit()


def get_meta(conn: sqlite3.Connection, slug: str) -> sqlite3.Row | None:
    row = conn.execute(
        "SELECT has_passphrase, expires_at FROM secrets WHERE slug = ?", (slug,)
    ).fetchone()
    if row is None or row["expires_at"] <= iso(utcnow()):
        return None
    return row


def consume_secret(conn: sqlite3.Connection, slug: str) -> sqlite3.Row | None:
    row = conn.execute(
        "DELETE FROM secrets WHERE slug = ?"
        " RETURNING ciphertext, nonce, has_passphrase, expires_at",
        (slug,),
    ).fetchone()
    conn.commit()
    if row is None or row["expires_at"] <= iso(utcnow()):
        return None
    return row


def purge_expired(conn: sqlite3.Connection) -> int:
    cur = conn.execute("DELETE FROM secrets WHERE expires_at <= ?", (iso(utcnow()),))
    conn.commit()
    return cur.rowcount
