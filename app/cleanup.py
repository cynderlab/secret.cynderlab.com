import sqlite3

from .config import load_settings
from .db import connect
from .store import purge_expired


def run(conn: sqlite3.Connection) -> int:
    deleted = purge_expired(conn)
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.execute("VACUUM")
    return deleted


def main() -> None:
    settings = load_settings()
    deleted = run(connect(settings.db_path))
    print(f"cleanup: purged {deleted} expired secret(s)")


if __name__ == "__main__":
    main()
