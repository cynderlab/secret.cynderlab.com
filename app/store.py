import sqlite3
from datetime import datetime, timedelta, timezone

MAX_ATTEMPTS = 5
LOCK_MINUTES = 5


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
    verifier_hash: bytes | None = None,
) -> None:
    conn.execute(
        "INSERT INTO secrets"
        " (slug, ciphertext, nonce, has_passphrase, created_at, expires_at, verifier_hash)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (slug, ciphertext, nonce, int(has_passphrase), iso(utcnow()), expires_at,
         verifier_hash),
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


def get_auth(conn: sqlite3.Connection, slug: str) -> sqlite3.Row | None:
    row = conn.execute(
        "SELECT verifier_hash, failed_attempts, locked_until, expires_at"
        " FROM secrets WHERE slug = ?", (slug,)
    ).fetchone()
    if row is None or row["expires_at"] <= iso(utcnow()):
        return None
    return row


def register_failure(conn: sqlite3.Connection, slug: str,
                     max_attempts: int = MAX_ATTEMPTS,
                     lock_minutes: int = LOCK_MINUTES) -> int | str:
    """Record one failed passphrase attempt. Returns attempts left, or "locked"
    when this failure reaches the limit (counter resets, slug locks flat)."""
    row = conn.execute(
        "UPDATE secrets SET failed_attempts = failed_attempts + 1 WHERE slug = ?"
        " RETURNING failed_attempts", (slug,)
    ).fetchone()
    if row is not None and row["failed_attempts"] >= max_attempts:
        conn.execute(
            "UPDATE secrets SET failed_attempts = 0, locked_until = ? WHERE slug = ?",
            (iso(utcnow() + timedelta(minutes=lock_minutes)), slug),
        )
        conn.commit()
        return "locked"
    conn.commit()
    return max_attempts - row["failed_attempts"] if row is not None else 0


def purge_expired(conn: sqlite3.Connection) -> int:
    cur = conn.execute("DELETE FROM secrets WHERE expires_at <= ?", (iso(utcnow()),))
    conn.commit()
    return cur.rowcount
