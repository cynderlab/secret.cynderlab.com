# secret.cynderlab.com — One-Time Secret Sharing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A minimal FastAPI web app at secret.cynderlab.com for sharing encrypted, burn-on-read secrets — the decryption key lives only in the link, never on the server.

**Architecture:** FastAPI + Jinja2 + SQLite (stdlib `sqlite3`, no ORM). Secrets are AES-256-GCM encrypted; the 256-bit key is generated per secret and carried only in the URL. Two symmetric paths: the web UI encrypts/decrypts **in the browser** (WebCrypto, key in the `#fragment`, never sent to the server), and a JSON API for agents/curl where the server encrypts/decrypts **in memory** (key in POST body, never stored, never logged). Reads are atomic burn-on-read (`DELETE ... RETURNING`). Deployed as a systemd **user** service (`systemctl --user`) with DB migration in `ExecStartPre` and an hourly cleanup timer.

**Tech Stack:** Python ≥3.12, uv, FastAPI, uvicorn, Jinja2, `cryptography`, SQLite (WAL), pytest + httpx TestClient, vanilla JS (WebCrypto), self-hosted fonts (JetBrains Mono, Barlow).

## Global Constraints

- **Security & privacy first.** Server must never persist a decryption key, plaintext secret, or client IP in the DB. No third-party requests from any page (fonts/JS/CSS all self-hosted). No analytics.
- **Crypto scheme `cynderlab.secret.v1`** (identical in Python and JS): `aes_key = HKDF-SHA256(ikm=link_key[32B], salt=(passphrase ? PBKDF2-HMAC-SHA256(passphrase, salt=utf8(slug), 310000 iters, 32B) : empty), info=utf8("cynderlab.secret.v1"), len=32)`; AES-256-GCM, 12-byte random nonce, AAD = `utf8(slug)`. Keys/slugs/blobs travel as **base64url without padding**.
- **Slug:** 22-char base64url of 16 random bytes, regex `^[A-Za-z0-9_-]{22}$`.
- **One read only:** any successful consume/reveal deletes the row first (atomic). Expired rows are never served.
- **Expiry:** optional date picker, max **30 days** (`SECRET_MAX_TTL_DAYS=30`); no date chosen → expires at now+30d.
- **Max secret size:** **256 KB** plaintext (`SECRET_MAX_BYTES=262144`).
- **Rate limit:** **20 secret creations / hour / IP** (`SECRET_RATE_LIMIT_PER_HOUR=20`), in-memory sliding window → run uvicorn with **exactly 1 worker**.
- **UI language: English only.** Tone: geek, modern, fun — but professional. Brand: ember/burn motif (Cynder → cinder).
- **Company data (footer + legal pages):** CYNDERLAB DIGITAL SL · CIF B27584010 · Vic (Barcelona) · hola@cynderlab.com · GitHub https://github.com/cynderlab/secret.cynderlab.com · corporate site https://cynderlab.com.
- **Env vars:** `SECRET_DB_PATH`, `SECRET_BASE_URL`, `SECRET_MAX_BYTES`, `SECRET_MAX_TTL_DAYS`, `SECRET_RATE_LIMIT_PER_HOUR`.
- All error paths (404, 410, 500, 413, 422, 429) land on branded pages (HTML) or structured JSON (`/api/*`). FastAPI auto-docs (`/docs`, `/openapi.json`) are **disabled**; `/llms.txt` is the API contract for agents.
- Timestamps stored as UTC strings `YYYY-MM-DDTHH:MM:SSZ` (lexicographically comparable).
- Commits: conventional commits (`feat:`, `test:`, `chore:`...). Run tests with `uv run pytest -q`.

## Design Direction (for all UI tasks)

- **Palette:** `--bg #0C1420` (deep navy), `--panel #121D2E`, `--line #22334D`, `--cyan #2CB9DD` (logo cyan, primary accent/links/buttons), `--cyan-bright #4FD8F7` (hover/focus), `--text #DCE7F2`, `--muted #7E8FA6`, `--ember #FF8A3D` (the burn color: one-time warnings, the "burned" state).
- **Type:** JetBrains Mono for display headings, code, slugs and links; Barlow Regular/Bold for body; Barlow SemiCondensed Bold (uppercase, letterspaced) for eyebrow labels. All self-hosted from `static/fonts/`.
- **Signature element:** the **burn motif** — the created-link panel is styled as terminal output with an ember-orange "READS LEFT: 1" fuse line; the reveal page shows an ember "🔥 burned" stamp once consumed. Everything else stays quiet and disciplined.
- **Quality floor:** responsive to mobile, visible keyboard focus (`:focus-visible` cyan outline), `prefers-reduced-motion` respected, real copy (no lorem).

## File Structure

```
pyproject.toml            # uv project, deps, pytest config
.env.example              # documented env vars
app/
  __init__.py
  config.py               # Settings dataclass + load_settings()
  db.py                   # connect() with pragmas + migrate() runner
  migrate.py              # python -m app.migrate  (used by ExecStartPre)
  crypto.py               # slug/key gen, derive_key, encrypt/decrypt (AES-256-GCM)
  store.py                # create/get_meta/consume/purge — all SQL lives here
  ratelimit.py            # in-memory sliding window + client_ip()
  api.py                  # JSON endpoints under /api
  web.py                  # HTML routes: /, /s/{slug}, /privacy, /legal, llms.txt, robots.txt
  main.py                 # create_app(): wiring, middleware, error handlers
  cleanup.py              # python -m app.cleanup  (used by timer)
migrations/
  001_init.sql
templates/
  base.html  home.html  secret.html  error.html  privacy.html  legal.html
static/
  css/app.css
  js/crypto.js  js/create.js  js/reveal.js
  fonts/  img/logo.png  favicon.svg
tests/
  conftest.py  test_config.py  test_db.py  test_crypto.py  test_store.py
  test_api_create.py  test_api_reveal.py  test_ratelimit.py  test_web.py  test_cleanup.py
deploy/
  secret-cynderlab.service
  secret-cynderlab-cleanup.service
  secret-cynderlab-cleanup.timer
  nginx-secret.cynderlab.com.conf
README.md
docs/superpowers/plans/2026-08-07-secret-sharing-app.md   (this file)
```

---

### Task 1: Project scaffolding + config module

**Files:**
- Create: `pyproject.toml`, `.env.example`, `app/__init__.py`, `app/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: nothing (first task).
- Produces: `app.config.Settings` (frozen dataclass with fields `db_path: str`, `base_url: str`, `max_secret_bytes: int`, `max_ttl_days: int`, `rate_limit_per_hour: int`) and `app.config.load_settings() -> Settings` which reads env vars at call time. Every later task reads config through `load_settings()`.

- [ ] **Step 1: Initialize the uv project**

```bash
cd /home/developer/Code/secret.cynderlab.com
uv init --bare --python ">=3.12"
uv add "fastapi>=0.115" "uvicorn[standard]>=0.30" "jinja2>=3.1" "cryptography>=43"
uv add --group dev "pytest>=8" "httpx>=0.27"
mkdir -p app tests
touch app/__init__.py
```

Then append to `pyproject.toml`:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 2: Write the failing test**

`tests/test_config.py`:

```python
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.config'`

- [ ] **Step 4: Write the implementation**

`app/config.py`:

```python
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    db_path: str
    base_url: str
    max_secret_bytes: int
    max_ttl_days: int
    rate_limit_per_hour: int


def load_settings() -> Settings:
    return Settings(
        db_path=os.environ.get("SECRET_DB_PATH", "data/secrets.db"),
        base_url=os.environ.get("SECRET_BASE_URL", "http://127.0.0.1:8321").rstrip("/"),
        max_secret_bytes=int(os.environ.get("SECRET_MAX_BYTES", "262144")),
        max_ttl_days=int(os.environ.get("SECRET_MAX_TTL_DAYS", "30")),
        rate_limit_per_hour=int(os.environ.get("SECRET_RATE_LIMIT_PER_HOUR", "20")),
    )
```

`.env.example`:

```bash
# Copy to .env and adjust. Loaded by systemd (EnvironmentFile), not by the app itself.
SECRET_DB_PATH=/home/developer/apps/secret.cynderlab.com/data/secrets.db
SECRET_BASE_URL=https://secret.cynderlab.com
SECRET_MAX_BYTES=262144
SECRET_MAX_TTL_DAYS=30
SECRET_RATE_LIMIT_PER_HOUR=20
```

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/test_config.py -v`
Expected: 2 PASS

- [ ] **Step 6: Update .gitignore and commit**

Ensure `.gitignore` covers `.env`, `data/`, `*.db`, `*.db-wal`, `*.db-shm` (append if missing).

```bash
git add pyproject.toml uv.lock .env.example .gitignore app/ tests/
git commit -m "feat: scaffold uv project with env-driven settings"
```

---

### Task 2: SQLite layer + migration runner

**Files:**
- Create: `app/db.py`, `app/migrate.py`, `migrations/001_init.sql`
- Test: `tests/test_db.py`

**Interfaces:**
- Consumes: `load_settings()` from Task 1 (only in `app/migrate.py`).
- Produces: `app.db.connect(db_path: str) -> sqlite3.Connection` (Row factory, WAL, busy_timeout, `check_same_thread=False`) and `app.db.migrate(conn) -> list[int]` (applies pending `migrations/NNN_*.sql`, returns versions applied). The `secrets` table schema: `slug TEXT PK, ciphertext BLOB, nonce BLOB, has_passphrase INTEGER, created_at TEXT, expires_at TEXT`. `python -m app.migrate` is the deploy migration entrypoint.

- [ ] **Step 1: Write the failing test**

`tests/test_db.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_db.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.db'`

- [ ] **Step 3: Write migration + implementation**

`migrations/001_init.sql`:

```sql
CREATE TABLE secrets (
    slug            TEXT PRIMARY KEY,
    ciphertext      BLOB NOT NULL,
    nonce           BLOB NOT NULL,
    has_passphrase  INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL
);

CREATE INDEX idx_secrets_expires_at ON secrets (expires_at);
```

`app/db.py`:

```python
import sqlite3
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"


def connect(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def migrate(conn: sqlite3.Connection) -> list[int]:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations"
        " (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    applied = {r["version"] for r in conn.execute("SELECT version FROM schema_migrations")}
    done = []
    for path in sorted(MIGRATIONS_DIR.glob("[0-9][0-9][0-9]_*.sql")):
        version = int(path.name.split("_")[0])
        if version in applied:
            continue
        conn.executescript(path.read_text())
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_at)"
            " VALUES (?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
            (version,),
        )
        conn.commit()
        done.append(version)
    return done
```

`app/migrate.py`:

```python
from .config import load_settings
from .db import connect, migrate


def main() -> None:
    settings = load_settings()
    applied = migrate(connect(settings.db_path))
    print(f"migrations applied: {applied or 'none (up to date)'}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_db.py -v`
Expected: 2 PASS. Also sanity-check the CLI: `SECRET_DB_PATH=/tmp/claude-mig.db uv run python -m app.migrate` prints `migrations applied: [1]`.

- [ ] **Step 5: Commit**

```bash
git add app/db.py app/migrate.py migrations/ tests/test_db.py
git commit -m "feat: sqlite connection helper and sql migration runner"
```

---

### Task 3: Crypto module (AES-256-GCM, key-in-URL scheme v1)

**Files:**
- Create: `app/crypto.py`
- Test: `tests/test_crypto.py`

**Interfaces:**
- Consumes: nothing app-internal (`cryptography` lib only).
- Produces (used by store/api/JS mirror):
  - `new_slug() -> str` (22-char base64url), `SLUG_RE` (compiled regex `^[A-Za-z0-9_-]{22}$`)
  - `new_key() -> bytes` (32 random bytes)
  - `b64u_encode(data: bytes) -> str` / `b64u_decode(s: str) -> bytes` (base64url, no padding)
  - `derive_key(link_key: bytes, slug: str, passphrase: str | None) -> bytes` (32B, scheme v1)
  - `encrypt(plaintext: bytes, aes_key: bytes, slug: str) -> tuple[bytes, bytes]` → `(nonce, ciphertext)`
  - `decrypt(nonce: bytes, ciphertext: bytes, aes_key: bytes, slug: str) -> bytes` (raises `cryptography.exceptions.InvalidTag` on wrong key/passphrase/tampering)
  - Constants: `HKDF_INFO = b"cynderlab.secret.v1"`, `PBKDF2_ITERATIONS = 310_000`

- [ ] **Step 1: Write the failing test**

`tests/test_crypto.py`:

```python
import pytest
from cryptography.exceptions import InvalidTag
from app import crypto


def test_slug_and_key_shapes():
    slug = crypto.new_slug()
    assert crypto.SLUG_RE.fullmatch(slug)
    assert len(crypto.new_key()) == 32
    assert crypto.new_slug() != crypto.new_slug()


def test_b64u_roundtrip_no_padding():
    data = bytes(range(32))
    s = crypto.b64u_encode(data)
    assert "=" not in s
    assert crypto.b64u_decode(s) == data


def test_encrypt_decrypt_roundtrip():
    slug, link_key = crypto.new_slug(), crypto.new_key()
    aes_key = crypto.derive_key(link_key, slug, None)
    nonce, ct = crypto.encrypt(b"deploy token: tk-123", aes_key, slug)
    assert crypto.decrypt(nonce, ct, aes_key, slug) == b"deploy token: tk-123"


def test_wrong_key_fails():
    slug = crypto.new_slug()
    aes_key = crypto.derive_key(crypto.new_key(), slug, None)
    nonce, ct = crypto.encrypt(b"x", aes_key, slug)
    bad = crypto.derive_key(crypto.new_key(), slug, None)
    with pytest.raises(InvalidTag):
        crypto.decrypt(nonce, ct, bad, slug)


def test_wrong_slug_aad_fails():
    slug, link_key = crypto.new_slug(), crypto.new_key()
    aes_key = crypto.derive_key(link_key, slug, None)
    nonce, ct = crypto.encrypt(b"x", aes_key, slug)
    with pytest.raises(InvalidTag):
        crypto.decrypt(nonce, ct, aes_key, crypto.new_slug())


def test_passphrase_changes_key_and_is_required():
    slug, link_key = crypto.new_slug(), crypto.new_key()
    with_pass = crypto.derive_key(link_key, slug, "correct horse")
    without = crypto.derive_key(link_key, slug, None)
    assert with_pass != without
    nonce, ct = crypto.encrypt(b"x", with_pass, slug)
    with pytest.raises(InvalidTag):
        crypto.decrypt(nonce, ct, crypto.derive_key(link_key, slug, "wrong"), slug)
    assert crypto.decrypt(nonce, ct, crypto.derive_key(link_key, slug, "correct horse"), slug) == b"x"


def test_known_vector_locks_scheme_v1():
    """Locks cross-language compatibility with static/js/crypto.js. Do not change."""
    link_key = bytes(range(32))
    slug = "AAAAAAAAAAAAAAAAAAAAAA"
    aes_key = crypto.derive_key(link_key, slug, "hunter2")
    assert crypto.b64u_encode(aes_key) == "aQ9zwdkp5wqhsrCL5-kxi7yy-sKCAfvDrl0DHgKd5KY"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_crypto.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.crypto'` (or ImportError)

- [ ] **Step 3: Write the implementation**

`app/crypto.py`:

```python
import base64
import re
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

HKDF_INFO = b"cynderlab.secret.v1"
PBKDF2_ITERATIONS = 310_000
SLUG_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")


def new_slug() -> str:
    return secrets.token_urlsafe(16)


def new_key() -> bytes:
    return secrets.token_bytes(32)


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def derive_key(link_key: bytes, slug: str, passphrase: str | None) -> bytes:
    salt = b""
    if passphrase:
        salt = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=slug.encode("utf-8"),
            iterations=PBKDF2_ITERATIONS,
        ).derive(passphrase.encode("utf-8"))
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=HKDF_INFO
    ).derive(link_key)


def encrypt(plaintext: bytes, aes_key: bytes, slug: str) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, slug.encode("utf-8"))
    return nonce, ciphertext


def decrypt(nonce: bytes, ciphertext: bytes, aes_key: bytes, slug: str) -> bytes:
    return AESGCM(aes_key).decrypt(nonce, ciphertext, slug.encode("utf-8"))
```

- [ ] **Step 4: Cross-check the pinned test vector independently**

The pinned value `aQ9zwdkp5wqhsrCL5-kxi7yy-sKCAfvDrl0DHgKd5KY` was derived with a stdlib-only PBKDF2+HKDF implementation, independent of the `cryptography` package. Confirm the implementation agrees:

Run: `uv run python -c "from app import crypto; print(crypto.b64u_encode(crypto.derive_key(bytes(range(32)), 'AAAAAAAAAAAAAAAAAAAAAA', 'hunter2')))"`
Expected: prints exactly `aQ9zwdkp5wqhsrCL5-kxi7yy-sKCAfvDrl0DHgKd5KY`. If it doesn't, the KDF wiring (PBKDF2 salt=slug, HKDF salt=pbkdf2-output, info constant) deviates from scheme v1 — fix `derive_key`, not the vector.

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_crypto.py -v`
Expected: 7 PASS

- [ ] **Step 6: Commit**

```bash
git add app/crypto.py tests/test_crypto.py
git commit -m "feat: aes-256-gcm crypto with key-in-url scheme v1"
```

---
### Task 4: Secret store (create / meta / burn-on-read consume / purge)

**Files:**
- Create: `app/store.py`
- Test: `tests/test_store.py`

**Interfaces:**
- Consumes: `app.db.connect/migrate` (Task 2), `app.crypto.SLUG_RE` (Task 3).
- Produces (all take a `sqlite3.Connection` as first arg; timestamps are `YYYY-MM-DDTHH:MM:SSZ` strings):
  - `utcnow() -> datetime` (tz-aware UTC), `iso(dt: datetime) -> str`
  - `create_secret(conn, slug: str, ciphertext: bytes, nonce: bytes, has_passphrase: bool, expires_at: str) -> None` (raises `sqlite3.IntegrityError` on duplicate slug)
  - `get_meta(conn, slug: str) -> sqlite3.Row | None` — columns `has_passphrase`, `expires_at`; returns `None` if missing **or expired**
  - `consume_secret(conn, slug: str) -> sqlite3.Row | None` — atomically deletes and returns columns `ciphertext`, `nonce`, `has_passphrase`; `None` if missing or expired (expired rows are deleted, never served)
  - `purge_expired(conn) -> int` — rows deleted

- [ ] **Step 1: Write the failing test**

`tests/test_store.py`:

```python
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
    import sqlite3
    store.create_secret(conn, SLUG, b"a", b"n", False, future())
    with pytest.raises(sqlite3.IntegrityError):
        store.create_secret(conn, SLUG, b"b", b"n", False, future())


def test_purge_expired(conn):
    store.create_secret(conn, "A" * 22, b"a", b"n", False, past())
    store.create_secret(conn, "B" * 22, b"b", b"n", False, future())
    assert store.purge_expired(conn) == 1
    assert conn.execute("SELECT slug FROM secrets").fetchone()["slug"] == "B" * 22
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_store.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.store'`

- [ ] **Step 3: Write the implementation**

`app/store.py`:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_store.py -v`
Expected: 5 PASS

- [ ] **Step 5: Commit**

```bash
git add app/store.py tests/test_store.py
git commit -m "feat: secret store with atomic burn-on-read and expiry"
```

---

### Task 5: App factory + JSON API for creation (server-side and client-side encrypted paths)

**Files:**
- Create: `app/main.py`, `app/api.py`, `tests/conftest.py`
- Test: `tests/test_api_create.py`

**Interfaces:**
- Consumes: `load_settings` (T1), `connect/migrate` (T2), `crypto` (T3), `store` (T4).
- Produces:
  - `app.main.create_app(settings: Settings | None = None) -> FastAPI` — wires DB (`app.state.db`), settings (`app.state.settings`), routers. Module-level `app = create_app()` for uvicorn. FastAPI constructed with `docs_url=None, redoc_url=None, openapi_url=None`.
  - `app.api.parse_expiry(raw: str | None, max_ttl_days: int) -> str` — `None` → now+max; accepts `YYYY-MM-DD` (means that day 23:59:59Z) or `YYYY-MM-DDTHH:MM:SSZ`; raises `ValueError` if past or beyond max.
  - `POST /api/secrets` JSON `{secret, passphrase?, expires_at?}` → 201 `{slug, link, link_api, expires_at}` where `link = f"{base_url}/s/{slug}#{key_b64u}"` and `link_api = f"{base_url}/api/secrets/{slug}/reveal"`. Server generates slug+key, encrypts, stores, forgets key.
  - `POST /api/secrets/encrypted` JSON `{slug, ciphertext, nonce, has_passphrase?, expires_at?}` (b64u strings; browser already encrypted) → 201 `{slug, expires_at}`. 409 on duplicate slug, 422 on bad slug/b64/expiry, 413 when plaintext or ciphertext exceeds the size limit.
- Later tasks (6, 7, 8) add routes/middleware to this same factory.

- [ ] **Step 1: Write the shared test fixture**

`tests/conftest.py`:

```python
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
        rate_limit_per_hour=1000,     # effectively off; Task 7 tests override this
    )
    defaults.update(overrides)
    return Settings(**defaults)


@pytest.fixture
def client(tmp_path):
    app = create_app(make_settings(tmp_path))
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
```

- [ ] **Step 2: Write the failing tests**

`tests/test_api_create.py`:

```python
from app import crypto


def test_create_server_side(client):
    r = client.post("/api/secrets", json={"secret": "tok-123"})
    assert r.status_code == 201
    body = r.json()
    assert crypto.SLUG_RE.fullmatch(body["slug"])
    assert body["link"].startswith(f"https://secret.test/s/{body['slug']}#")
    key = body["link"].split("#", 1)[1]
    assert len(crypto.b64u_decode(key)) == 32
    assert body["link_api"] == f"https://secret.test/api/secrets/{body['slug']}/reveal"


def test_create_rejects_oversize(client):
    r = client.post("/api/secrets", json={"secret": "x" * 262145})
    assert r.status_code == 413


def test_create_rejects_past_expiry(client):
    r = client.post("/api/secrets", json={"secret": "x", "expires_at": "2001-01-01"})
    assert r.status_code == 422


def test_create_rejects_expiry_beyond_max(client):
    r = client.post("/api/secrets", json={"secret": "x", "expires_at": "2999-01-01"})
    assert r.status_code == 422


def test_create_encrypted_path(client):
    slug, link_key = crypto.new_slug(), crypto.new_key()
    aes_key = crypto.derive_key(link_key, slug, None)
    nonce, ct = crypto.encrypt(b"hello", aes_key, slug)
    r = client.post("/api/secrets/encrypted", json={
        "slug": slug,
        "ciphertext": crypto.b64u_encode(ct),
        "nonce": crypto.b64u_encode(nonce),
    })
    assert r.status_code == 201
    assert r.json()["slug"] == slug


def test_create_encrypted_duplicate_slug_conflicts(client):
    slug = crypto.new_slug()
    payload = {"slug": slug, "ciphertext": crypto.b64u_encode(b"ct"), "nonce": crypto.b64u_encode(b"n" * 12)}
    assert client.post("/api/secrets/encrypted", json=payload).status_code == 201
    assert client.post("/api/secrets/encrypted", json=payload).status_code == 409


def test_create_encrypted_rejects_bad_slug(client):
    r = client.post("/api/secrets/encrypted", json={
        "slug": "../etc/passwd", "ciphertext": "YQ", "nonce": "YQ"})
    assert r.status_code == 422
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_api_create.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.main'`

- [ ] **Step 4: Write the implementation**

`app/api.py`:

```python
import base64
import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from . import crypto, store
from .config import Settings

router = APIRouter(prefix="/api")


class CreateSecret(BaseModel):
    secret: str
    passphrase: str | None = None
    expires_at: str | None = None


class CreateEncrypted(BaseModel):
    slug: str
    ciphertext: str
    nonce: str
    has_passphrase: bool = False
    expires_at: str | None = None


def parse_expiry(raw: str | None, max_ttl_days: int) -> str:
    now = store.utcnow()
    latest = now + timedelta(days=max_ttl_days)
    if raw is None:
        return store.iso(latest)
    try:
        if len(raw) == 10:  # YYYY-MM-DD -> end of that day, UTC
            dt = datetime.strptime(raw, "%Y-%m-%d").replace(
                hour=23, minute=59, second=59, tzinfo=timezone.utc)
        else:
            dt = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError("expires_at must be YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ")
    if dt <= now:
        raise ValueError("expires_at is in the past")
    if dt > latest:
        raise ValueError(f"expires_at exceeds the {max_ttl_days}-day maximum")
    return store.iso(dt)


def _b64u_or_422(field: str, value: str) -> bytes:
    try:
        return crypto.b64u_decode(value)
    except (ValueError, base64.binascii.Error):
        raise HTTPException(422, f"{field} is not valid base64url")


@router.post("/secrets", status_code=201)
def create_secret(body: CreateSecret, request: Request):
    settings: Settings = request.app.state.settings
    conn: sqlite3.Connection = request.app.state.db
    plaintext = body.secret.encode("utf-8")
    if len(plaintext) > settings.max_secret_bytes:
        raise HTTPException(413, f"secret exceeds {settings.max_secret_bytes} bytes")
    try:
        expires_at = parse_expiry(body.expires_at, settings.max_ttl_days)
    except ValueError as e:
        raise HTTPException(422, str(e))
    slug, link_key = crypto.new_slug(), crypto.new_key()
    aes_key = crypto.derive_key(link_key, slug, body.passphrase or None)
    nonce, ciphertext = crypto.encrypt(plaintext, aes_key, slug)
    store.create_secret(conn, slug, ciphertext, nonce, bool(body.passphrase), expires_at)
    return {
        "slug": slug,
        "link": f"{settings.base_url}/s/{slug}#{crypto.b64u_encode(link_key)}",
        "link_api": f"{settings.base_url}/api/secrets/{slug}/reveal",
        "expires_at": expires_at,
    }


@router.post("/secrets/encrypted", status_code=201)
def create_secret_encrypted(body: CreateEncrypted, request: Request):
    settings: Settings = request.app.state.settings
    conn: sqlite3.Connection = request.app.state.db
    if not crypto.SLUG_RE.fullmatch(body.slug):
        raise HTTPException(422, "slug must match ^[A-Za-z0-9_-]{22}$")
    ciphertext = _b64u_or_422("ciphertext", body.ciphertext)
    nonce = _b64u_or_422("nonce", body.nonce)
    if len(ciphertext) > settings.max_secret_bytes + 16:  # GCM tag overhead
        raise HTTPException(413, f"ciphertext exceeds {settings.max_secret_bytes} bytes")
    try:
        expires_at = parse_expiry(body.expires_at, settings.max_ttl_days)
    except ValueError as e:
        raise HTTPException(422, str(e))
    try:
        store.create_secret(conn, body.slug, ciphertext, nonce, body.has_passphrase, expires_at)
    except sqlite3.IntegrityError:
        raise HTTPException(409, "slug already exists, generate a new one")
    return {"slug": body.slug, "expires_at": expires_at}
```

`app/main.py`:

```python
from fastapi import FastAPI

from . import api
from .config import Settings, load_settings
from .db import connect, migrate


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    application = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    application.state.settings = settings
    application.state.db = connect(settings.db_path)
    migrate(application.state.db)
    application.include_router(api.router)
    return application


app = create_app()
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_api_create.py -v`
Expected: 7 PASS (and the full suite still green: `uv run pytest -q`)

- [ ] **Step 6: Commit**

```bash
git add app/main.py app/api.py tests/conftest.py tests/test_api_create.py
git commit -m "feat: app factory and secret creation api (server-side and pre-encrypted)"
```

---

### Task 6: JSON API for reading (meta / consume / reveal)

**Files:**
- Modify: `app/api.py` (append endpoints)
- Test: `tests/test_api_reveal.py`

**Interfaces:**
- Consumes: everything from Task 5.
- Produces:
  - `GET /api/secrets/{slug}` → 200 `{slug, has_passphrase, expires_at}` or 404 `{detail}`. Does NOT burn.
  - `POST /api/secrets/{slug}/consume` (empty body) → 200 `{ciphertext, nonce, has_passphrase}` (b64u) and **burns**; 404 if missing/expired/already read. Used by browser JS which decrypts locally.
  - `POST /api/secrets/{slug}/reveal` JSON `{key, passphrase?}` → 200 `{secret}` (server decrypts in memory) and **burns**; 404 if gone; 422 bad key encoding; **410 with an explicit "burned" message when the key/passphrase is wrong** — the secret was already destroyed by the attempt. Used by curl/agents.

- [ ] **Step 1: Write the failing tests**

`tests/test_api_reveal.py`:

```python
from app import crypto


def make(client, secret="s3cret", passphrase=None):
    payload = {"secret": secret}
    if passphrase:
        payload["passphrase"] = passphrase
    body = client.post("/api/secrets", json=payload).json()
    key = body["link"].split("#", 1)[1]
    return body["slug"], key


def test_meta_reports_without_burning(client):
    slug, _ = make(client, passphrase="pw")
    for _ in range(2):
        r = client.get(f"/api/secrets/{slug}")
        assert r.status_code == 200
        assert r.json()["has_passphrase"] is True


def test_meta_404_for_unknown(client):
    assert client.get("/api/secrets/" + "x" * 22).status_code == 404


def test_reveal_roundtrip_and_burn(client):
    slug, key = make(client, secret="deploy: tk-42")
    r = client.post(f"/api/secrets/{slug}/reveal", json={"key": key})
    assert r.status_code == 200
    assert r.json()["secret"] == "deploy: tk-42"
    assert client.post(f"/api/secrets/{slug}/reveal", json={"key": key}).status_code == 404
    assert client.get(f"/api/secrets/{slug}").status_code == 404


def test_reveal_with_passphrase(client):
    slug, key = make(client, passphrase="correct horse")
    r = client.post(f"/api/secrets/{slug}/reveal", json={"key": key, "passphrase": "correct horse"})
    assert r.status_code == 200
    assert r.json()["secret"] == "s3cret"


def test_wrong_key_burns_and_returns_410(client):
    slug, key = make(client)
    bad = crypto.b64u_encode(crypto.new_key())
    r = client.post(f"/api/secrets/{slug}/reveal", json={"key": bad})
    assert r.status_code == 410
    assert "burned" in r.json()["detail"].lower()
    assert client.get(f"/api/secrets/{slug}").status_code == 404  # gone for real


def test_consume_returns_ciphertext_and_burns(client):
    slug, key = make(client, secret="webflow")
    r = client.post(f"/api/secrets/{slug}/consume")
    assert r.status_code == 200
    body = r.json()
    aes_key = crypto.derive_key(crypto.b64u_decode(key), slug, None)
    plaintext = crypto.decrypt(
        crypto.b64u_decode(body["nonce"]), crypto.b64u_decode(body["ciphertext"]), aes_key, slug)
    assert plaintext == b"webflow"
    assert client.post(f"/api/secrets/{slug}/consume").status_code == 404
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_api_reveal.py -v`
Expected: FAIL with 404s/405s (routes don't exist yet)

- [ ] **Step 3: Append the endpoints**

Append to `app/api.py`:

```python
from cryptography.exceptions import InvalidTag


class RevealRequest(BaseModel):
    key: str
    passphrase: str | None = None


@router.get("/secrets/{slug}")
def secret_meta(slug: str, request: Request):
    row = store.get_meta(request.app.state.db, slug)
    if row is None:
        raise HTTPException(404, "secret not found: never existed, expired, or already read")
    return {"slug": slug, "has_passphrase": bool(row["has_passphrase"]),
            "expires_at": row["expires_at"]}


@router.post("/secrets/{slug}/consume")
def consume(slug: str, request: Request):
    row = store.consume_secret(request.app.state.db, slug)
    if row is None:
        raise HTTPException(404, "secret not found: never existed, expired, or already read")
    return {"ciphertext": crypto.b64u_encode(row["ciphertext"]),
            "nonce": crypto.b64u_encode(row["nonce"]),
            "has_passphrase": bool(row["has_passphrase"])}


@router.post("/secrets/{slug}/reveal")
def reveal(slug: str, body: RevealRequest, request: Request):
    try:
        link_key = crypto.b64u_decode(body.key)
    except (ValueError, base64.binascii.Error):
        raise HTTPException(422, "key is not valid base64url")
    if len(link_key) != 32:
        raise HTTPException(422, "key must decode to 32 bytes")
    row = store.consume_secret(request.app.state.db, slug)
    if row is None:
        raise HTTPException(404, "secret not found: never existed, expired, or already read")
    aes_key = crypto.derive_key(link_key, slug, body.passphrase or None)
    try:
        plaintext = crypto.decrypt(row["nonce"], row["ciphertext"], aes_key, slug)
    except InvalidTag:
        raise HTTPException(
            410, "wrong key or passphrase — the secret was consumed by this attempt and is now burned")
    return {"secret": plaintext.decode("utf-8")}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_api_reveal.py -v`
Expected: 6 PASS (full suite green: `uv run pytest -q`)

- [ ] **Step 5: Commit**

```bash
git add app/api.py tests/test_api_reveal.py
git commit -m "feat: meta, consume and reveal endpoints with burn-on-read semantics"
```

---

### Task 7: Rate limiting + client IP resolution

**Files:**
- Create: `app/ratelimit.py`
- Modify: `app/main.py` (attach limiter to app.state), `app/api.py` (guard the two create endpoints)
- Test: `tests/test_ratelimit.py`

**Interfaces:**
- Consumes: app factory (T5).
- Produces:
  - `app.ratelimit.RateLimiter(limit: int, window_seconds: int = 3600)` with `check(key: str, now: float | None = None) -> int | None` — `None` = allowed (hit recorded), int = seconds until next allowed (429 Retry-After).
  - `app.ratelimit.client_ip(request) -> str` — returns `X-Real-IP` header **only when the direct peer is localhost** (nginx sets it from Cloudflare's `CF-Connecting-IP`); otherwise the socket peer address.
  - `app.state.limiter` on the app; both create endpoints raise 429 with `Retry-After` header when exhausted.

- [ ] **Step 1: Write the failing tests**

`tests/test_ratelimit.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_ratelimit.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.ratelimit'`

- [ ] **Step 3: Write the implementation**

`app/ratelimit.py`:

```python
import threading
import time
from collections import defaultdict, deque

from fastapi import Request

LOCALHOST = {"127.0.0.1", "::1", None}


class RateLimiter:
    """In-memory sliding window. Correct only with a single worker process."""

    def __init__(self, limit: int, window_seconds: int = 3600):
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, now: float | None = None) -> int | None:
        now = time.monotonic() if now is None else now
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - self.window:
                q.popleft()
            if len(q) >= self.limit:
                return max(1, int(self.window - (now - q[0])) + 1)
            q.append(now)
            return None


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client else None
    if peer in LOCALHOST and (real := request.headers.get("x-real-ip")):
        return real
    return peer or "unknown"
```

In `app/main.py`, inside `create_app` after `application.state.db = ...`, add:

```python
from .ratelimit import RateLimiter
application.state.limiter = RateLimiter(settings.rate_limit_per_hour)
```

(move the import to the top of the file with the others)

In `app/api.py` add a helper and call it **first** in both `create_secret` and `create_secret_encrypted`:

```python
from fastapi.responses import JSONResponse


def enforce_create_limit(request: Request) -> None:
    from .ratelimit import client_ip
    retry_after = request.app.state.limiter.check(client_ip(request))
    if retry_after is not None:
        raise HTTPException(429, "rate limit exceeded: try again later",
                            headers={"Retry-After": str(retry_after)})
```

First line of `create_secret` and `create_secret_encrypted`: `enforce_create_limit(request)`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_ratelimit.py -v` then `uv run pytest -q`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add app/ratelimit.py app/main.py app/api.py tests/test_ratelimit.py
git commit -m "feat: per-ip sliding-window rate limit on secret creation"
```

---
### Task 8: Web foundation — base template, design system, home page, client-side encryption

**Files:**
- Create: `app/web.py`, `templates/base.html`, `templates/home.html`, `static/css/app.css`, `static/js/crypto.js`, `static/js/create.js`, `static/favicon.svg`, `static/img/logo.png` (copy), `static/fonts/*` (copy)
- Modify: `app/main.py` (mount static, include web router)
- Test: `tests/test_web.py`

**Interfaces:**
- Consumes: app factory (T5), create-encrypted endpoint (T5), crypto scheme + pinned test vector (T3).
- Produces: `app.web.router` (HTML routes; this task adds `GET /`), `app.web.templates` (Jinja2Templates instance reused by error handlers in Task 10), `static/js/crypto.js` exposing `window.CynderCrypto = { b64uEncode, b64uDecode, randomBytes, newSlug, deriveAesKey, encryptSecret, decryptSecret }` (exact mirror of `app/crypto.py`). Templates `base.html` (blocks: `title`, `content`, `scripts`) with site header + footer (GitHub, Privacy, Legal, cynderlab.com, company line).

- [ ] **Step 1: Copy brand assets**

```bash
mkdir -p static/img static/fonts static/css static/js
cp /home/developer/.claude/skills/cynderlab-docs/assets/logo_trans.png static/img/logo.png
cp /home/developer/.claude/skills/cynderlab-docs/assets/fonts/JetBrainsMono-Regular.ttf \
   /home/developer/.claude/skills/cynderlab-docs/assets/fonts/JetBrainsMono-Bold.ttf \
   /home/developer/.claude/skills/cynderlab-docs/assets/fonts/Barlow-Regular.ttf \
   /home/developer/.claude/skills/cynderlab-docs/assets/fonts/Barlow-Bold.ttf \
   /home/developer/.claude/skills/cynderlab-docs/assets/fonts/BarlowSemiCondensed-Bold.ttf \
   static/fonts/
```

- [ ] **Step 2: Write the failing tests**

`tests/test_web.py`:

```python
def test_home_renders(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "burn" in r.text.lower()
    for element_id in ("secret-input", "expiry-input", "passphrase-input", "create-btn", "result-panel"):
        assert f'id="{element_id}"' in r.text


def test_footer_links(client):
    r = client.get("/")
    for href in ("https://github.com/cynderlab/secret.cynderlab.com", "/privacy", "/legal",
                 "https://cynderlab.com"):
        assert href in r.text
    assert "CYNDERLAB DIGITAL SL" in r.text


def test_static_assets_served(client):
    assert client.get("/static/css/app.css").status_code == 200
    assert client.get("/static/js/crypto.js").status_code == 200
    assert client.get("/static/js/create.js").status_code == 200
    assert client.get("/static/img/logo.png").status_code == 200
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_web.py -v`
Expected: FAIL (404s — no web router or static mount yet)

- [ ] **Step 4: Write `app/web.py` and wire it in `app/main.py`**

`app/web.py`:

```python
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def home(request: Request):
    settings = request.app.state.settings
    return templates.TemplateResponse(request, "home.html", {
        "max_ttl_days": settings.max_ttl_days,
        "max_kb": settings.max_secret_bytes // 1024,
    })
```

In `app/main.py`, inside `create_app` after `application.include_router(api.router)`:

```python
from fastapi.staticfiles import StaticFiles
from . import web

application.include_router(web.router)
application.mount("/static", StaticFiles(directory=str(web.BASE_DIR / "static")), name="static")
```

(imports at top of file)

- [ ] **Step 5: Write the templates**

`templates/base.html`:

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}Cynderlab Secrets — burn after reading{% endblock %}</title>
  <meta name="description" content="Share a secret with a link that self-destructs after one read. Encrypted in your browser; the server never sees the key.">
  <link rel="icon" href="/static/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="/static/css/app.css">
</head>
<body>
  <header class="site-header">
    <a class="brand" href="/">
      <img src="/static/img/logo.png" alt="Cynderlab logo" height="34">
      <span class="brand-name">secret<span class="accent">.</span>cynderlab</span>
    </a>
    <nav class="site-nav">
      <a href="/#how-it-works">How it works</a>
      <a href="/#agents">For agents</a>
    </nav>
  </header>
  <main class="wrap">{% block content %}{% endblock %}</main>
  <footer class="site-footer">
    <p class="mono ember">// burn after reading</p>
    <nav>
      <a href="https://github.com/cynderlab/secret.cynderlab.com">Source on GitHub</a>
      <a href="/privacy">Privacy policy</a>
      <a href="/legal">Legal notice</a>
      <a href="https://cynderlab.com">cynderlab.com</a>
    </nav>
    <p class="footer-legal">CYNDERLAB DIGITAL SL · CIF B27584010 · Vic (Barcelona) ·
      <a href="mailto:hola@cynderlab.com">hola@cynderlab.com</a></p>
  </footer>
  {% block scripts %}{% endblock %}
</body>
</html>
```

`templates/home.html`:

```html
{% extends "base.html" %}
{% block content %}
<section class="hero">
  <p class="eyebrow">one link · one read · then ash</p>
  <h1>Share secrets that<br><span class="accent">self-destruct.</span></h1>
  <p class="lede">Paste a password, an API key, a config. Get a link. The secret is encrypted
  <strong>in your browser</strong> — the key stays in the link and never touches our server.
  First read burns it. So could we peek? No. Literally, cryptographically, no.</p>
</section>

<section class="creator">
  <form id="create-form" autocomplete="off">
    <label class="mono" for="secret-input">$ cat your_secret.txt</label>
    <textarea id="secret-input" rows="8" required maxlength="262144"
      placeholder="Paste the secret here. Up to {{ max_kb }} KB of text."></textarea>
    <div class="options">
      <div class="option">
        <label for="expiry-input">Expires on <span class="muted">(optional, max {{ max_ttl_days }} days)</span></label>
        <input type="date" id="expiry-input">
      </div>
      <div class="option">
        <label for="passphrase-input">Passphrase <span class="muted">(optional second factor)</span></label>
        <input type="password" id="passphrase-input" placeholder="share it via another channel">
      </div>
    </div>
    <button type="submit" id="create-btn">Encrypt &amp; create link</button>
    <p id="create-error" class="error" hidden></p>
  </form>

  <div id="result-panel" class="terminal" hidden>
    <p class="mono muted"># secret stored — this link is the only copy of the key</p>
    <p class="mono link-line"><output id="result-link"></output></p>
    <p class="mono ember">READS LEFT: 1 ▓▓▓▓▓▓▓▓▓▓ — burns on first open</p>
    <p class="mono muted" id="result-expiry"></p>
    <div class="row">
      <button type="button" id="copy-btn">Copy link</button>
      <a href="/" class="ghost-btn">New secret</a>
    </div>
  </div>
</section>

<section id="how-it-works" class="explain">
  <h2>How it works <span class="mono muted">(for humans)</span></h2>
  <ol>
    <li><strong>Encrypt.</strong> Your browser generates a random 256-bit key and encrypts the
      secret with AES-256-GCM. Only the encrypted blob is uploaded.</li>
    <li><strong>Share.</strong> The key rides in the link after the <code>#</code> — browsers
      never send that part to any server. Send the link to one person.</li>
    <li><strong>Burn.</strong> The first open destroys the secret on our server. Expired secrets
      burn too, read or not. Nothing to hack, nothing to subpoena.</li>
  </ol>
  <p>Add a passphrase and the link alone is not enough — tell the passphrase to the recipient
  through a different channel (a call, in person). Wrong passphrase on the API burns the secret:
  that is a feature, not a bug.</p>
</section>

<section id="agents" class="explain">
  <h2>How it works <span class="mono muted">(for agents &amp; scripts)</span></h2>
  <p>Machine-readable docs live at <a href="/llms.txt"><code>/llms.txt</code></a>. Quick start:</p>
  <pre class="terminal"><code># create (server encrypts in memory, key returned once in the link)
curl -s https://secret.cynderlab.com/api/secrets \
  -H 'content-type: application/json' \
  -d '{"secret": "the payload", "expires_at": "2026-09-01"}'

# reveal (burns the secret; key = the part after '#' in the link)
curl -s https://secret.cynderlab.com/api/secrets/&lt;slug&gt;/reveal \
  -H 'content-type: application/json' \
  -d '{"key": "&lt;key&gt;"}'</code></pre>
  <p class="muted">One read only. A reveal with a wrong key still burns the secret — retry is
  impossible by design.</p>
</section>
{% endblock %}
{% block scripts %}
<script src="/static/js/crypto.js"></script>
<script src="/static/js/create.js"></script>
{% endblock %}
```

- [ ] **Step 6: Write the stylesheet and favicon**

`static/favicon.svg`:

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <rect width="32" height="32" rx="6" fill="#0C1420"/>
  <text x="16" y="22" font-family="monospace" font-size="15" font-weight="bold"
        fill="#2CB9DD" text-anchor="middle">s#</text>
</svg>
```

`static/css/app.css`:

```css
@font-face { font-family: "JetBrains Mono"; src: url("/static/fonts/JetBrainsMono-Regular.ttf"); font-weight: 400; font-display: swap; }
@font-face { font-family: "JetBrains Mono"; src: url("/static/fonts/JetBrainsMono-Bold.ttf"); font-weight: 700; font-display: swap; }
@font-face { font-family: "Barlow"; src: url("/static/fonts/Barlow-Regular.ttf"); font-weight: 400; font-display: swap; }
@font-face { font-family: "Barlow"; src: url("/static/fonts/Barlow-Bold.ttf"); font-weight: 700; font-display: swap; }
@font-face { font-family: "Barlow SemiCondensed"; src: url("/static/fonts/BarlowSemiCondensed-Bold.ttf"); font-weight: 700; font-display: swap; }

:root {
  --bg: #0C1420; --panel: #121D2E; --line: #22334D;
  --cyan: #2CB9DD; --cyan-bright: #4FD8F7;
  --text: #DCE7F2; --muted: #7E8FA6; --ember: #FF8A3D;
  --mono: "JetBrains Mono", ui-monospace, monospace;
  --body: "Barlow", system-ui, sans-serif;
}
* { box-sizing: border-box; margin: 0; }
body { background: var(--bg); color: var(--text); font-family: var(--body);
  font-size: 1.05rem; line-height: 1.6; min-height: 100vh;
  display: flex; flex-direction: column; }
a { color: var(--cyan); text-decoration: none; }
a:hover { color: var(--cyan-bright); text-decoration: underline; }
:focus-visible { outline: 2px solid var(--cyan); outline-offset: 2px; }
code, pre, .mono { font-family: var(--mono); font-size: 0.92em; }
.accent { color: var(--cyan); }
.ember { color: var(--ember); }
.muted { color: var(--muted); }

.site-header { display: flex; justify-content: space-between; align-items: center;
  gap: 1rem; padding: 1rem 1.5rem; border-bottom: 1px solid var(--line); flex-wrap: wrap; }
.brand { display: flex; align-items: center; gap: .6rem; color: var(--text); }
.brand:hover { text-decoration: none; }
.brand-name { font-family: var(--mono); font-weight: 700; letter-spacing: -.02em; }
.site-nav { display: flex; gap: 1.25rem; font-family: "Barlow SemiCondensed", var(--body);
  text-transform: uppercase; letter-spacing: .08em; font-size: .85rem; }

.wrap { flex: 1; width: min(46rem, 100% - 2.5rem); margin-inline: auto; padding-block: 2.5rem; }

.hero { margin-bottom: 2.5rem; }
.eyebrow { font-family: var(--mono); color: var(--ember); font-size: .85rem;
  letter-spacing: .12em; text-transform: uppercase; margin-bottom: .75rem; }
.hero h1 { font-family: var(--mono); font-weight: 700; font-size: clamp(1.9rem, 5.5vw, 3rem);
  line-height: 1.15; margin-bottom: 1rem; }
.lede { color: var(--muted); max-width: 38rem; }
.lede strong { color: var(--text); }

.creator form, .terminal { background: var(--panel); border: 1px solid var(--line);
  border-radius: 10px; padding: 1.25rem; }
.creator label { display: block; margin-bottom: .4rem; font-size: .9rem; }
textarea, input[type="date"], input[type="password"], input[type="text"] {
  width: 100%; background: var(--bg); color: var(--text); border: 1px solid var(--line);
  border-radius: 6px; padding: .6rem .75rem; font-family: var(--mono); font-size: .95rem; }
textarea { resize: vertical; }
.options { display: grid; grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr));
  gap: 1rem; margin-block: 1rem; }
button, .ghost-btn { font-family: var(--mono); font-weight: 700; font-size: 1rem;
  border-radius: 6px; padding: .65rem 1.25rem; cursor: pointer; }
button { background: var(--cyan); color: #06121B; border: 1px solid var(--cyan); }
button:hover { background: var(--cyan-bright); border-color: var(--cyan-bright); }
.ghost-btn { display: inline-block; background: none; border: 1px solid var(--line); }
.row { display: flex; gap: .75rem; margin-top: 1rem; flex-wrap: wrap; align-items: center; }
.error { color: var(--ember); margin-top: .75rem; }

.terminal { margin-top: 1.5rem; overflow-x: auto; }
.terminal p { margin-block: .35rem; }
.link-line output { word-break: break-all; color: var(--cyan-bright); }
pre.terminal { line-height: 1.5; }

.explain { margin-top: 3rem; }
.explain h2 { font-family: var(--mono); font-size: 1.3rem; margin-bottom: .75rem; }
.explain ol { padding-left: 1.25rem; display: grid; gap: .5rem; margin-bottom: .75rem; }

.site-footer { border-top: 1px solid var(--line); padding: 1.5rem; text-align: center;
  font-size: .9rem; color: var(--muted); display: grid; gap: .5rem; }
.site-footer nav { display: flex; gap: 1.25rem; justify-content: center; flex-wrap: wrap; }

.reveal-box { text-align: left; }
.secret-output { white-space: pre-wrap; word-break: break-word; background: var(--bg);
  border: 1px solid var(--line); border-radius: 6px; padding: 1rem; margin-block: 1rem; }
.burned-stamp { display: inline-block; font-family: var(--mono); font-weight: 700;
  color: var(--ember); border: 2px solid var(--ember); border-radius: 4px;
  padding: .15rem .6rem; transform: rotate(-3deg); text-transform: uppercase;
  letter-spacing: .1em; }

@media (prefers-reduced-motion: no-preference) {
  .terminal:not([hidden]) { animation: rise .25s ease-out; }
  @keyframes rise { from { opacity: 0; transform: translateY(6px); } }
}
```

- [ ] **Step 7: Write the browser crypto mirror**

`static/js/crypto.js`:

```javascript
/* Mirror of app/crypto.py — scheme cynderlab.secret.v1.
 * Test vector: linkKey=bytes 0..31, slug="AAAAAAAAAAAAAAAAAAAAAA", passphrase="hunter2"
 * => b64u(aesKeyBits) === "aQ9zwdkp5wqhsrCL5-kxi7yy-sKCAfvDrl0DHgKd5KY" (tests/test_crypto.py) */
(function () {
  "use strict";
  const te = new TextEncoder(), td = new TextDecoder();
  const HKDF_INFO = te.encode("cynderlab.secret.v1");
  const PBKDF2_ITERATIONS = 310000;

  function b64uEncode(bytes) {
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  }
  function b64uDecode(str) {
    const s = atob(str.replaceAll("-", "+").replaceAll("_", "/"));
    return Uint8Array.from(s, c => c.charCodeAt(0));
  }
  function randomBytes(n) { return crypto.getRandomValues(new Uint8Array(n)); }
  function newSlug() { return b64uEncode(randomBytes(16)); }

  async function deriveAesKey(linkKey, slug, passphrase, usages) {
    let salt = new Uint8Array(0);
    if (passphrase) {
      const pk = await crypto.subtle.importKey("raw", te.encode(passphrase), "PBKDF2", false, ["deriveBits"]);
      salt = new Uint8Array(await crypto.subtle.deriveBits(
        { name: "PBKDF2", hash: "SHA-256", salt: te.encode(slug), iterations: PBKDF2_ITERATIONS },
        pk, 256));
    }
    const ikm = await crypto.subtle.importKey("raw", linkKey, "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info: HKDF_INFO },
      ikm, { name: "AES-GCM", length: 256 }, false, usages);
  }

  async function encryptSecret(plaintext, slug, passphrase) {
    const linkKey = randomBytes(32);
    const aesKey = await deriveAesKey(linkKey, slug, passphrase, ["encrypt"]);
    const nonce = randomBytes(12);
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: te.encode(slug) },
      aesKey, te.encode(plaintext));
    return { key: b64uEncode(linkKey), nonce: b64uEncode(nonce), ciphertext: b64uEncode(new Uint8Array(ct)) };
  }

  async function decryptSecret(ciphertextB64, nonceB64, keyB64, slug, passphrase) {
    const aesKey = await deriveAesKey(b64uDecode(keyB64), slug, passphrase, ["decrypt"]);
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64uDecode(nonceB64), additionalData: te.encode(slug) },
      aesKey, b64uDecode(ciphertextB64));
    return td.decode(pt);
  }

  window.CynderCrypto = { b64uEncode, b64uDecode, randomBytes, newSlug, deriveAesKey, encryptSecret, decryptSecret };
})();
```

- [ ] **Step 8: Write the create-page script**

`static/js/create.js`:

```javascript
(function () {
  "use strict";
  const $ = id => document.getElementById(id);
  const form = $("create-form");
  if (!form) return;

  const MAX_BYTES = 262144;
  const expiry = $("expiry-input");
  const today = new Date();
  const plusDays = d => { const x = new Date(today); x.setDate(x.getDate() + d); return x.toISOString().slice(0, 10); };
  expiry.min = plusDays(1);
  expiry.max = plusDays(30);

  function fail(message) {
    const el = $("create-error");
    el.textContent = message;
    el.hidden = false;
    $("create-btn").disabled = false;
  }

  form.addEventListener("submit", async event => {
    event.preventDefault();
    $("create-error").hidden = true;
    $("create-btn").disabled = true;
    const secret = $("secret-input").value;
    if (new TextEncoder().encode(secret).length > MAX_BYTES) {
      return fail("Secret exceeds 256 KB. Trim it or split it.");
    }
    const passphrase = $("passphrase-input").value || null;
    try {
      for (let attempt = 0; attempt < 3; attempt++) {
        const slug = CynderCrypto.newSlug();
        const enc = await CynderCrypto.encryptSecret(secret, slug, passphrase);
        const res = await fetch("/api/secrets/encrypted", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            slug, ciphertext: enc.ciphertext, nonce: enc.nonce,
            has_passphrase: Boolean(passphrase),
            expires_at: expiry.value || null,
          }),
        });
        if (res.status === 409) continue;          // slug collision: rebuild with a new slug
        if (res.status === 429) return fail("Rate limit reached. Try again in a while.");
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          return fail(body.detail || `Could not store the secret (HTTP ${res.status}).`);
        }
        const body = await res.json();
        $("result-link").textContent = `${location.origin}/s/${slug}#${enc.key}`;
        $("result-expiry").textContent = `# expires ${body.expires_at} if never read`;
        form.hidden = true;
        $("result-panel").hidden = false;
        return;
      }
      fail("Could not allocate a link. Try again.");
    } catch (err) {
      fail("Encryption failed in this browser. It needs WebCrypto (any modern browser).");
    }
  });

  $("copy-btn").addEventListener("click", async () => {
    await navigator.clipboard.writeText($("result-link").textContent);
    $("copy-btn").textContent = "Copied ✔";
    setTimeout(() => { $("copy-btn").textContent = "Copy link"; }, 1500);
  });
})();
```

- [ ] **Step 9: Run tests to verify they pass**

Run: `uv run pytest tests/test_web.py -v` then `uv run pytest -q`
Expected: all PASS

- [ ] **Step 10: Manual cross-language crypto verification (browser ↔ Python)**

Run: `uv run uvicorn app.main:app --port 8321` and open `http://127.0.0.1:8321`. In the browser devtools console:

```javascript
const lk = Uint8Array.from({length: 32}, (_, i) => i);
CynderCrypto.deriveAesKey(lk, "AAAAAAAAAAAAAAAAAAAAAA", "hunter2", ["encrypt"]);
// deriveKey is non-extractable; verify via deriveBits variant instead:
crypto.subtle.importKey("raw", lk, "HKDF", false, ["deriveBits"]).then(async ikm => {
  const pk = await crypto.subtle.importKey("raw", new TextEncoder().encode("hunter2"), "PBKDF2", false, ["deriveBits"]);
  const salt = new Uint8Array(await crypto.subtle.deriveBits({name:"PBKDF2", hash:"SHA-256",
    salt: new TextEncoder().encode("AAAAAAAAAAAAAAAAAAAAAA"), iterations: 310000}, pk, 256));
  const bits = new Uint8Array(await crypto.subtle.deriveBits({name:"HKDF", hash:"SHA-256", salt,
    info: new TextEncoder().encode("cynderlab.secret.v1")}, ikm, 256));
  console.log(CynderCrypto.b64uEncode(bits));
});
```

Expected: prints exactly `aQ9zwdkp5wqhsrCL5-kxi7yy-sKCAfvDrl0DHgKd5KY` (the vector pinned in `tests/test_crypto.py`). Also create a secret through the UI and confirm the result panel shows a `/s/<slug>#<key>` link.

- [ ] **Step 11: Commit**

```bash
git add app/web.py app/main.py templates/ static/ tests/test_web.py
git commit -m "feat: home page with in-browser encryption and cynderlab design system"
```

---

### Task 9: Reveal page (`/s/{slug}`) with click-to-reveal and burned state

**Files:**
- Create: `templates/secret.html`, `static/js/reveal.js`
- Modify: `app/web.py` (add route)
- Test: `tests/test_web.py` (append)

**Interfaces:**
- Consumes: `GET /api/secrets/{slug}` meta + `POST /api/secrets/{slug}/consume` (T6), `CynderCrypto.decryptSecret` (T8), `templates` (T8).
- Produces: `GET /s/{slug}` → always 200 with the reveal shell (existence is checked by JS via the meta endpoint so link-previewing bots never burn a secret, and so the page itself reveals nothing). Invalid slug format → 404 (Task 10's handler renders it). Template carries `data-slug` on `#reveal-root`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_web.py`:

```python
def test_reveal_page_renders_shell(client):
    slug = "A" * 22
    r = client.get(f"/s/{slug}")
    assert r.status_code == 200
    assert f'data-slug="{slug}"' in r.text
    assert 'id="reveal-btn"' in r.text


def test_reveal_page_never_contains_secret_data(client):
    body = client.post("/api/secrets", json={"secret": "topsecret123"}).json()
    r = client.get(f"/s/{body['slug']}")
    assert "topsecret123" not in r.text          # shell only; JS fetches ciphertext on click


def test_reveal_page_invalid_slug_404(client):
    assert client.get("/s/short").status_code == 404
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_web.py -v`
Expected: new tests FAIL with 404 (route missing)

- [ ] **Step 3: Add the route**

Append to `app/web.py`:

```python
from fastapi import HTTPException

from .crypto import SLUG_RE


@router.get("/s/{slug}", response_class=HTMLResponse)
def reveal_page(slug: str, request: Request):
    if not SLUG_RE.fullmatch(slug):
        raise HTTPException(404)
    return templates.TemplateResponse(request, "secret.html", {"slug": slug})
```

(move imports to the top of the file)

- [ ] **Step 4: Write the template**

`templates/secret.html`:

```html
{% extends "base.html" %}
{% block title %}A secret awaits — Cynderlab Secrets{% endblock %}
{% block content %}
<div id="reveal-root" class="terminal reveal-box" data-slug="{{ slug }}">
  <section id="state-loading">
    <p class="mono muted">$ checking secret status…</p>
  </section>

  <section id="state-ready" hidden>
    <p class="eyebrow">incoming transmission</p>
    <h1 class="mono">Someone sent you a secret.</h1>
    <p class="lede">It can be read <strong class="ember">exactly once</strong>. When you reveal
    it, it is erased from the server — make sure you are ready to copy it now.</p>
    <div class="option" id="passphrase-box" hidden>
      <label for="reveal-passphrase">This secret requires a passphrase</label>
      <input type="password" id="reveal-passphrase" placeholder="ask the sender">
    </div>
    <div class="row">
      <button type="button" id="reveal-btn">Reveal — and burn</button>
    </div>
    <p id="reveal-error" class="error" hidden></p>
  </section>

  <section id="state-secret" hidden>
    <p><span class="burned-stamp">burned</span></p>
    <p class="lede">Copy it now — the server already forgot it. Reloading this page will not
    bring it back.</p>
    <pre class="secret-output"><code id="secret-text"></code></pre>
    <div class="row">
      <button type="button" id="copy-secret-btn">Copy secret</button>
      <a class="ghost-btn" href="/">Share one back</a>
    </div>
  </section>

  <section id="state-gone" hidden>
    <p class="eyebrow">nothing here but ash</p>
    <h1 class="mono">This secret is gone.</h1>
    <p class="lede">It was read once, it expired, or it never existed. That is the whole point —
    we cannot recover it, and neither can anyone else. Ask the sender for a new link.</p>
    <p class="row"><a class="ghost-btn" href="/">Create a secret</a></p>
  </section>

  <section id="state-nokey" hidden>
    <p class="eyebrow">key missing</p>
    <h1 class="mono">This link is incomplete.</h1>
    <p class="lede">The decryption key travels after the <code>#</code> in the link and this
    request arrived without it. Copy the <strong>full</strong> link and try again — the secret
    has not been burned.</p>
  </section>
</div>
{% endblock %}
{% block scripts %}
<script src="/static/js/crypto.js"></script>
<script src="/static/js/reveal.js"></script>
{% endblock %}
```

- [ ] **Step 5: Write the reveal script**

`static/js/reveal.js`:

```javascript
(function () {
  "use strict";
  const $ = id => document.getElementById(id);
  const root = $("reveal-root");
  if (!root) return;
  const slug = root.dataset.slug;
  const key = location.hash.slice(1);
  let needsPassphrase = false;
  let cached = null;    // {ciphertext, nonce} kept so a wrong passphrase can be retried locally

  const states = ["state-loading", "state-ready", "state-secret", "state-gone", "state-nokey"];
  function show(state) { for (const s of states) $(s).hidden = s !== state; }
  function fail(message) {
    const el = $("reveal-error");
    el.textContent = message;
    el.hidden = false;
    $("reveal-btn").disabled = false;
  }

  async function init() {
    if (!key) return show("state-nokey");
    const res = await fetch(`/api/secrets/${slug}`);
    if (!res.ok) return show("state-gone");
    const meta = await res.json();
    needsPassphrase = meta.has_passphrase;
    $("passphrase-box").hidden = !needsPassphrase;
    show("state-ready");
  }

  async function reveal() {
    $("reveal-error").hidden = true;
    $("reveal-btn").disabled = true;
    const passphrase = needsPassphrase ? $("reveal-passphrase").value : null;
    if (needsPassphrase && !passphrase) return fail("Enter the passphrase first.");
    if (!cached) {
      const res = await fetch(`/api/secrets/${slug}/consume`, { method: "POST" });
      if (!res.ok) return show("state-gone");
      cached = await res.json();
    }
    try {
      const text = await CynderCrypto.decryptSecret(cached.ciphertext, cached.nonce, key, slug, passphrase);
      $("secret-text").textContent = text;
      show("state-secret");
    } catch (err) {
      if (needsPassphrase) {
        fail("Wrong passphrase. The secret is already burned on the server, but you can retry here — do not close this tab.");
      } else {
        fail("Decryption failed: the key in this link does not match. The secret is burned.");
      }
    }
  }

  $("reveal-btn").addEventListener("click", reveal);
  $("copy-secret-btn").addEventListener("click", async () => {
    await navigator.clipboard.writeText($("secret-text").textContent);
    $("copy-secret-btn").textContent = "Copied ✔";
    setTimeout(() => { $("copy-secret-btn").textContent = "Copy secret"; }, 1500);
  });
  init();
})();
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/test_web.py -v` then `uv run pytest -q`
Expected: all PASS

- [ ] **Step 7: Manual end-to-end check**

With `uv run uvicorn app.main:app --port 8321`: create a secret in the UI (with and without passphrase), open the link in a private window, reveal, confirm the plaintext matches and a reload shows the "gone" state. Also confirm `/s/<slug>` opened **without** the `#key` shows the "incomplete link" state without burning (then the full link still works).

- [ ] **Step 8: Commit**

```bash
git add templates/secret.html static/js/reveal.js app/web.py tests/test_web.py
git commit -m "feat: click-to-reveal secret page with burn and gone states"
```

---
### Task 10: Security headers, branded error pages, robots.txt

**Files:**
- Create: `templates/error.html`
- Modify: `app/main.py` (middleware + exception handlers), `app/web.py` (robots.txt)
- Test: `tests/test_web.py` (append)

**Interfaces:**
- Consumes: app factory (T5), `templates` (T8).
- Produces: every response carries the security headers below; `/api/*` and `/s/*` responses carry `Cache-Control: no-store`; any HTML-path error (404, 405, 410, 429, 500…) renders `error.html` (branded, links home); `/api/*` errors stay JSON `{detail}`. `GET /robots.txt` disallows `/s/` and `/api/`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_web.py`:

```python
def test_security_headers_on_every_response(client):
    r = client.get("/")
    csp = r.headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"


def test_no_store_on_sensitive_paths(client):
    assert client.get("/s/" + "A" * 22).headers["cache-control"] == "no-store"
    assert client.get("/api/secrets/" + "A" * 22).headers["cache-control"] == "no-store"
    assert "no-store" not in client.get("/").headers.get("cache-control", "")


def test_html_404_is_branded(client):
    r = client.get("/does-not-exist")
    assert r.status_code == 404
    assert "CYNDERLAB DIGITAL SL" in r.text       # base template rendered
    assert "text/html" in r.headers["content-type"]


def test_api_404_stays_json(client):
    r = client.get("/api/secrets/" + "A" * 22)
    assert "application/json" in r.headers["content-type"]
    assert "detail" in r.json()


def test_robots_txt(client):
    r = client.get("/robots.txt")
    assert r.status_code == 200
    assert "Disallow: /s/" in r.text
    assert "Disallow: /api/" in r.text
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_web.py -v`
Expected: new tests FAIL (missing headers/handlers/route)

- [ ] **Step 3: Write the error template**

`templates/error.html`:

```html
{% extends "base.html" %}
{% block title %}{{ status }} — Cynderlab Secrets{% endblock %}
{% block content %}
<div class="terminal reveal-box">
  <p class="eyebrow">http {{ status }}</p>
  <h1 class="mono">{{ heading }}</h1>
  <p class="lede">{{ message }}</p>
  <p class="row"><a class="ghost-btn" href="/">Back to safety</a></p>
</div>
{% endblock %}
```

- [ ] **Step 4: Add middleware and handlers**

In `app/main.py`, add imports and extend `create_app` (after routers are included):

```python
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import web

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
        "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

ERROR_COPY = {
    404: ("Nothing at this address.", "The page you asked for does not exist. If you followed a secret link, the secret may simply be gone — burned or expired."),
    405: ("Wrong method.", "That endpoint exists, but not for this HTTP method. See /llms.txt for the API contract."),
    410: ("Burned.", "This resource was consumed and no longer exists. That is by design."),
    429: ("Slow down.", "You hit the rate limit for creating secrets. Wait a bit and try again."),
    500: ("Something broke on our side.", "The error has been logged without any of your data in it. Try again in a minute."),
}


def _security_headers_middleware(application: FastAPI) -> None:
    @application.middleware("http")
    async def add_security_headers(request, call_next):
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        if request.url.path.startswith(("/s/", "/api/")):
            response.headers["Cache-Control"] = "no-store"
        return response


def _error_handlers(application: FastAPI) -> None:
    @application.exception_handler(StarletteHTTPException)
    async def http_error(request, exc):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code,
                                headers=getattr(exc, "headers", None))
        heading, message = ERROR_COPY.get(exc.status_code, ("Unexpected error.", str(exc.detail)))
        return web.templates.TemplateResponse(
            request, "error.html",
            {"status": exc.status_code, "heading": heading, "message": message},
            status_code=exc.status_code)

    @application.exception_handler(Exception)
    async def server_error(request, exc):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": "internal server error"}, status_code=500)
        heading, message = ERROR_COPY[500]
        return web.templates.TemplateResponse(
            request, "error.html",
            {"status": 500, "heading": heading, "message": message}, status_code=500)
```

Call both from `create_app` before `return application`:

```python
_security_headers_middleware(application)
_error_handlers(application)
```

Append to `app/web.py`:

```python
from fastapi.responses import PlainTextResponse


@router.get("/robots.txt", response_class=PlainTextResponse)
def robots():
    return "User-agent: *\nDisallow: /s/\nDisallow: /api/\nAllow: /\n"
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: all PASS (note: `conftest.py` already uses `raise_server_exceptions=False` so the 500 path is testable if needed)

- [ ] **Step 6: Commit**

```bash
git add templates/error.html app/main.py app/web.py tests/test_web.py
git commit -m "feat: security headers, branded error pages and robots.txt"
```

---

### Task 11: llms.txt + privacy policy + legal notice

**Files:**
- Create: `templates/privacy.html`, `templates/legal.html`
- Modify: `app/web.py` (three routes)
- Test: `tests/test_web.py` (append)

**Interfaces:**
- Consumes: `templates`, footer links from T8 (`/privacy`, `/legal`, `/llms.txt` already referenced).
- Produces: `GET /llms.txt` (text/plain API contract for agents, rendered with the configured base_url), `GET /privacy`, `GET /legal` (HTML).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_web.py`:

```python
def test_llms_txt_documents_api(client):
    r = client.get("/llms.txt")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]
    for fragment in ("POST /api/secrets", "/reveal", "/consume", "one read",
                     "https://secret.test"):
        assert fragment in r.text


def test_privacy_and_legal_pages(client):
    p = client.get("/privacy")
    assert p.status_code == 200 and "CYNDERLAB DIGITAL SL" in p.text
    l = client.get("/legal")
    assert l.status_code == 200 and "B27584010" in l.text
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_web.py -v`
Expected: new tests FAIL with 404

- [ ] **Step 3: Add the routes**

Append to `app/web.py`:

```python
LLMS_TXT = """\
# Cynderlab Secrets — one-time secret sharing
# Base URL: {base}
# Everything below is the full API contract. No auth. Rate limit: 20 creations/hour/IP.

## What this service does
Store a text secret (max 256 KB), get a link. The secret is AES-256-GCM encrypted;
the decryption key exists ONLY in the link. Every secret allows exactly one read
("burn on read") and expires after at most 30 days even if never read.

## Create a secret (server-side encryption, in memory only)
POST {base}/api/secrets
  {{"secret": "<text>", "passphrase": "<optional>", "expires_at": "<optional YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ, max 30 days>"}}
  -> 201 {{"slug", "link", "link_api", "expires_at"}}
  "link" is for humans (browser decrypts; key after '#').
  The key is the part of "link" after '#'. The server does not keep it.

## Read a secret (burns it)
POST {base}/api/secrets/<slug>/reveal
  {{"key": "<key from the link>", "passphrase": "<if one was set>"}}
  -> 200 {{"secret": "<plaintext>"}}
  -> 404 if unknown, expired or already read
  -> 410 if key/passphrase wrong — the attempt CONSUMED the secret; it cannot be retried

## Check without burning
GET {base}/api/secrets/<slug>  -> 200 {{"slug", "has_passphrase", "expires_at"}} | 404

## Advanced: client-side encryption (what the web UI does)
POST {base}/api/secrets/encrypted
  {{"slug": "<22-char base64url you generate>", "ciphertext": "<b64url>", "nonce": "<b64url>",
   "has_passphrase": false, "expires_at": null}}
  Scheme cynderlab.secret.v1: aes_key = HKDF-SHA256(ikm=link_key,
  salt = passphrase ? PBKDF2-HMAC-SHA256(passphrase, salt=utf8(slug), 310000 iters) : empty,
  info = "cynderlab.secret.v1"); AES-256-GCM, 12-byte nonce, AAD = utf8(slug).
GET {base}/api/secrets/<slug>/consume does the reverse (POST, burns, returns ciphertext).

## Rules for agents
- Treat the link/key as the secret itself. Do not log it, do not store it.
- One read only: fetch the secret exactly when you need it, not before.
- On 404/410 do not retry: the secret is gone. Ask the human for a new link.

Operated by CYNDERLAB DIGITAL SL (https://cynderlab.com) — hola@cynderlab.com
Source: https://github.com/cynderlab/secret.cynderlab.com
"""


@router.get("/llms.txt", response_class=PlainTextResponse)
def llms_txt(request: Request):
    return LLMS_TXT.format(base=request.app.state.settings.base_url)


@router.get("/privacy", response_class=HTMLResponse)
def privacy(request: Request):
    return templates.TemplateResponse(request, "privacy.html", {})


@router.get("/legal", response_class=HTMLResponse)
def legal(request: Request):
    return templates.TemplateResponse(request, "legal.html", {})
```

- [ ] **Step 4: Write the pages**

`templates/privacy.html`:

```html
{% extends "base.html" %}
{% block title %}Privacy policy — Cynderlab Secrets{% endblock %}
{% block content %}
<article class="explain">
  <h1 class="mono">Privacy policy</h1>
  <p class="lede">Short version: we designed this service so that there is almost nothing about
  you for us to have.</p>

  <h2>What we store</h2>
  <ul>
    <li><strong>The encrypted secret</strong> (an AES-256-GCM blob), its creation and expiry
      timestamps, and whether a passphrase was set. We never hold the decryption key: it exists
      only in the link, so we cannot read your secrets — by construction, not by promise.</li>
    <li><strong>Nothing else in the database.</strong> No accounts, no emails, no IP addresses,
      no cookies, no analytics, no third-party requests.</li>
  </ul>

  <h2>What we process transiently</h2>
  <ul>
    <li>Your IP address, in memory only, to rate-limit secret creation. It is never written to
      the database.</li>
    <li>Standard web-server logs (IP, path, timestamp) kept briefly for security and abuse
      response. Secret links carry the key after the <code>#</code>, which browsers never send —
      so keys cannot appear in logs. API requests carry keys in request bodies, which are not
      logged.</li>
    <li>If you use the <code>/api/secrets</code> endpoint, the plaintext passes through server
      memory during encryption/decryption and is immediately discarded. Use the web UI or the
      <code>/encrypted</code> endpoint if you prefer that the server never sees plaintext.</li>
  </ul>

  <h2>Retention</h2>
  <p>Secrets are deleted on first read, at expiry (30 days maximum), and swept hourly by an
  automated cleanup job. Deleted means deleted: there are no backups of secret content.</p>

  <h2>Your rights &amp; contact</h2>
  <p>Data controller: CYNDERLAB DIGITAL SL, Vic (Barcelona), Spain. For any privacy request
  (GDPR arts. 15–22) write to <a href="mailto:hola@cynderlab.com">hola@cynderlab.com</a>. Given
  the design, in most cases the honest answer will be: we hold no data about you.</p>
</article>
{% endblock %}
```

`templates/legal.html`:

```html
{% extends "base.html" %}
{% block title %}Legal notice — Cynderlab Secrets{% endblock %}
{% block content %}
<article class="explain">
  <h1 class="mono">Legal notice</h1>
  <h2>Site owner</h2>
  <p>CYNDERLAB DIGITAL SL · CIF B27584010 · Vic (Barcelona), Spain ·
  <a href="mailto:hola@cynderlab.com">hola@cynderlab.com</a> ·
  <a href="https://cynderlab.com">cynderlab.com</a>. Information provided in compliance with
  Spanish Law 34/2002 (LSSI-CE).</p>

  <h2>Acceptable use</h2>
  <p>This service is offered free of charge for sharing sensitive text between parties who
  trust each other. You may not use it to distribute unlawful content, malware, or content that
  infringes third-party rights. We cannot inspect encrypted content, but we will cooperate with
  lawful orders regarding metadata and will remove specific slugs when required.</p>

  <h2>Warranty &amp; liability</h2>
  <p>The service is provided "as is", without warranty of any kind. Secrets are destroyed after
  one read or at expiry; CYNDERLAB DIGITAL SL is not liable for lost secrets, for links shared
  over insecure channels, or for any damages arising from use of the service. The source code is
  publicly auditable at
  <a href="https://github.com/cynderlab/secret.cynderlab.com">GitHub</a>.</p>

  <h2>Governing law</h2>
  <p>These terms are governed by Spanish law. Disputes are subject to the courts of Vic
  (Barcelona), notwithstanding mandatory consumer jurisdiction rules.</p>
</article>
{% endblock %}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest -q`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add app/web.py templates/privacy.html templates/legal.html tests/test_web.py
git commit -m "feat: llms.txt api contract plus privacy and legal pages"
```

---

### Task 12: Cleanup job (`python -m app.cleanup`)

**Files:**
- Create: `app/cleanup.py`
- Test: `tests/test_cleanup.py`

**Interfaces:**
- Consumes: `load_settings` (T1), `connect` (T2), `store.purge_expired` (T4).
- Produces: `app.cleanup.run(conn) -> int` (purges expired rows, checkpoints WAL, VACUUMs, returns rows deleted) and `python -m app.cleanup` entrypoint for the systemd timer.

- [ ] **Step 1: Write the failing test**

`tests/test_cleanup.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cleanup.py -v`
Expected: FAIL with `ImportError` (no `app.cleanup`)

- [ ] **Step 3: Write the implementation**

`app/cleanup.py`:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_cleanup.py -v` then `uv run pytest -q`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add app/cleanup.py tests/test_cleanup.py
git commit -m "feat: expired-secret cleanup job for the systemd timer"
```

---

### Task 13: Deployment — systemd user units, nginx config, README

**Files:**
- Create: `deploy/secret-cynderlab.service`, `deploy/secret-cynderlab-cleanup.service`, `deploy/secret-cynderlab-cleanup.timer`, `deploy/nginx-secret.cynderlab.com.conf`
- Modify: `README.md` (replace stub)

**Interfaces:**
- Consumes: `python -m app.migrate` (T2), `python -m app.cleanup` (T12), `.env.example` (T1), single-worker constraint (T7).
- Produces: deployable artifacts. Convention: app lives at `~/apps/secret.cynderlab.com` on the server, `uv` at `%h/.local/bin/uv`, app listens on `127.0.0.1:8321`.

- [ ] **Step 1: Write the service unit (migration in ExecStartPre)**

`deploy/secret-cynderlab.service`:

```ini
[Unit]
Description=Cynderlab Secrets (secret.cynderlab.com)
After=network-online.target

[Service]
WorkingDirectory=%h/apps/secret.cynderlab.com
EnvironmentFile=%h/apps/secret.cynderlab.com/.env
ExecStartPre=%h/.local/bin/uv run python -m app.migrate
ExecStart=%h/.local/bin/uv run uvicorn app.main:app --host 127.0.0.1 --port 8321 --workers 1 --no-server-header
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=%h/apps/secret.cynderlab.com

[Install]
WantedBy=default.target
```

- [ ] **Step 2: Write the cleanup service + timer**

`deploy/secret-cynderlab-cleanup.service`:

```ini
[Unit]
Description=Cynderlab Secrets — purge expired secrets

[Service]
Type=oneshot
WorkingDirectory=%h/apps/secret.cynderlab.com
EnvironmentFile=%h/apps/secret.cynderlab.com/.env
ExecStart=%h/.local/bin/uv run python -m app.cleanup
```

`deploy/secret-cynderlab-cleanup.timer`:

```ini
[Unit]
Description=Hourly cleanup of expired secrets

[Timer]
OnCalendar=hourly
RandomizedDelaySec=5m
Persistent=true

[Install]
WantedBy=timers.target
```

- [ ] **Step 3: Write the nginx config**

`deploy/nginx-secret.cynderlab.com.conf`:

```nginx
# secret.cynderlab.com — origin behind Cloudflare.
# TLS terminates here with a Cloudflare Origin Certificate; Cloudflare proxies the edge.
server {
    listen 443 ssl;
    http2 on;
    server_name secret.cynderlab.com;

    ssl_certificate     /etc/nginx/ssl/secret.cynderlab.com.origin.pem;
    ssl_certificate_key /etc/nginx/ssl/secret.cynderlab.com.origin.key;

    client_max_body_size 1m;

    # Privacy: keep the path but never log query strings (defense in depth; keys travel
    # in fragments/bodies and never reach the server, but belt and braces).
    log_format secrets_privacy '$remote_addr - [$time_local] "$request_method $uri" '
                               '$status $body_bytes_sent';
    access_log /var/log/nginx/secret.cynderlab.com.access.log secrets_privacy;

    location / {
        proxy_pass http://127.0.0.1:8321;
        proxy_set_header Host $host;
        # Real client IP as seen by Cloudflare; the app trusts this header only
        # because the request arrives via localhost.
        proxy_set_header X-Real-IP $http_cf_connecting_ip;
        proxy_set_header X-Forwarded-Proto https;
    }
}

server {
    listen 80;
    server_name secret.cynderlab.com;
    return 301 https://secret.cynderlab.com$request_uri;
}
```

- [ ] **Step 4: Write the README**

Replace `README.md` content with:

```markdown
# secret.cynderlab.com

One-time secret sharing by [Cynderlab](https://cynderlab.com). Paste a secret, get a link,
first read burns it. The decryption key lives only in the link — the server stores an
AES-256-GCM blob it cannot decrypt.

## Security model, in one paragraph

The web UI encrypts in your browser (WebCrypto); the key rides in the URL fragment (`#`),
which browsers never transmit. The API path encrypts/decrypts in server memory only (key in
POST bodies, never stored, never logged). Every secret is destroyed on first read and expires
after at most 30 days. The database holds no keys, no plaintext, no IPs. Scheme details:
`/llms.txt` and `app/crypto.py` (`cynderlab.secret.v1`).

## Development

```bash
uv sync
uv run pytest
uv run uvicorn app.main:app --port 8321 --reload
```

Configuration is env-driven; see `.env.example`.

## Deployment (systemd --user)

```bash
# on the server, as the service user
git clone https://github.com/cynderlab/secret.cynderlab.com ~/apps/secret.cynderlab.com
cd ~/apps/secret.cynderlab.com
cp .env.example .env && $EDITOR .env
uv sync --no-dev

mkdir -p ~/.config/systemd/user
cp deploy/secret-cynderlab.service deploy/secret-cynderlab-cleanup.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now secret-cynderlab.service secret-cynderlab-cleanup.timer
loginctl enable-linger "$USER"      # keep user services running after logout
```

DB migrations run automatically in `ExecStartPre` on every (re)start. The timer purges
expired secrets hourly and VACUUMs the database.

Upgrades: `git pull && uv sync --no-dev && systemctl --user restart secret-cynderlab.service`.

nginx origin config: `deploy/nginx-secret.cynderlab.com.conf` (Cloudflare in front; the app
must run with exactly **one** worker — the rate limiter is in-process).

## License

MIT — see [LICENSE](LICENSE).
```

- [ ] **Step 5: Validate and run the full suite**

Run: `systemd-analyze --user verify deploy/secret-cynderlab.service deploy/secret-cynderlab-cleanup.service deploy/secret-cynderlab-cleanup.timer || true` (warnings about %h paths not existing locally are acceptable; syntax errors are not) and `uv run pytest -q`.
Expected: no unit syntax errors; full test suite PASS.

- [ ] **Step 6: Commit**

```bash
git add deploy/ README.md
git commit -m "chore: systemd user units, nginx origin config and deployment docs"
```

---

## Final verification (after all tasks)

- [ ] `uv run pytest -q` — entire suite green.
- [ ] Manual E2E per Task 8 Step 10 and Task 9 Step 7 (browser create/reveal, passphrase flow, gone state, incomplete-link state).
- [ ] `curl` E2E against a local uvicorn: create via `POST /api/secrets`, reveal via `POST .../reveal`, second reveal → 404.
- [ ] Check `/`, `/privacy`, `/legal`, `/llms.txt`, `/robots.txt`, a 404, and `/s/<fake-slug>` all render branded and with security headers.

## Explicit non-goals (v1)

File uploads, accounts, secret listing/management, multiple reads, webhooks, i18n, Prometheus metrics, and Google Cloud KMS (rejected during design: adds a GCP dependency without protecting against the main threat, DB theft — the key-in-URL scheme already does).

