# secret.cynderlab.com

One-time secret sharing by [Cynderlab](https://cynderlab.com). Paste a secret, get a link,
first read burns it. The decryption key lives only in the link — the server stores an
AES-256-GCM blob it cannot decrypt.

**Live at [secret.cynderlab.com](https://secret.cynderlab.com)**

## Features

- **Burn on read** — every secret allows exactly one read (atomic `DELETE … RETURNING`);
  a second visit lands on a 404.
- **Key in the URL, never on the server** — a stolen database is a pile of undecryptable blobs.
- **Zero-knowledge web flow** — the browser encrypts with WebCrypto; the key travels in the
  URL fragment (`#`), which browsers never send to any server.
- **Self-destruct by default** — unread secrets vanish after 7 days; the prefilled calendar
  picker only lets senders choose an earlier date. Expired secrets are never served and the
  process itself sweeps them hourly (no cron, no timers).
- **Optional passphrase, server-gated** — a second factor mixed into the key derivation. The
  server verifies a derived proof (never the passphrase itself) **before** releasing or
  burning anything: a typo never destroys a secret, and 5 failed attempts lock that secret
  for 5 minutes. Attempts are counted per secret — no IP or User-Agent tracking.
- **Abuse control** — 20 secret creations/hour/IP (in-memory sliding window), 256 KB max.
- **Nothing to leak** — no accounts, no cookies, no analytics, no third-party requests, no IPs
  in the database. Strict CSP, `no-store` on sensitive paths, branded error pages.

## Security model, in one paragraph

Everything cryptographic happens in your browser (WebCrypto): key generation, encryption,
decryption. The key rides in the URL fragment (`#`), which browsers never transmit, and the
server only ever stores and serves encrypted blobs. Every secret is destroyed on first read
and expires after at most 7 days. The database holds no keys, no plaintext, no IPs. Broken
links — missing key, expired, already read — all resolve to the same 404.

### Crypto scheme (`cynderlab.secret.v1`)

```
aes_key = HKDF-SHA256(
    ikm  = link_key (32 random bytes, lives only in the URL),
    salt = passphrase ? PBKDF2-HMAC-SHA256(passphrase, salt=utf8(slug), 310000 iters) : empty,
    info = "cynderlab.secret.v1")
AES-256-GCM · 12-byte nonce · AAD = utf8(slug)

# passphrase gate (proof sent to the server instead of the passphrase):
verifier = PBKDF2-HMAC-SHA256(passphrase, salt=utf8(slug + ".verify"), 310000 iters)
server stores sha256(verifier) only · constant-time compare · 5 fails = 5-minute lock
```

Implemented twice — `app/crypto.py` (server) and `static/js/crypto.js` (browser) — and locked
together by a pinned test vector (`tests/test_crypto.py`) plus `verify_crypto.mjs`, a Node
script that encrypts in JS and decrypts in Python.

## Transport endpoints (browser only)

The server exposes only ciphertext transport — every byte of plaintext and every key stays
in the browser:

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/secrets/encrypted` | POST | Store a blob the browser already encrypted (+ verifier if passphrase-protected) |
| `/api/secrets/{slug}` | GET | Metadata check — does **not** burn |
| `/api/secrets/{slug}/consume` | POST | Burn and return the ciphertext (browser decrypts). Passphrase-protected secrets require the verifier: wrong proof → 403 with `attempts_left` (no burn); 5th failure → 429, locked 5 minutes |

There is deliberately no endpoint that accepts or returns plaintext.

## Stack

FastAPI · SQLite (stdlib `sqlite3`, WAL, no ORM) · Jinja2 · vanilla JS + WebCrypto ·
`cryptography` · uv · pytest. One process, one worker, no external services.

```
app/            config, db + migrations runner, crypto, store, api, web, ratelimit, cleanup
migrations/     numbered .sql files, applied by `python -m app.migrate` (ExecStartPre)
templates/      Jinja2 pages (home, how-it-works, reveal, legal, errors)
static/         css, fonts (self-hosted), crypto.js/create.js/reveal.js
deploy/         systemd user unit + nginx origin config
tests/          70+ tests: crypto vectors, burn semantics, passphrase gate, api, i18n, pages
```

## Configuration

Env-driven — see `.env.example`:

| Variable | Default | Meaning |
|---|---|---|
| `SECRET_DB_PATH` | `data/secrets.db` | SQLite file location |
| `SECRET_BASE_URL` | `http://127.0.0.1:8001` | Public base URL used in generated links |
| `SECRET_MAX_BYTES` | `262144` | Max plaintext size (256 KB) |
| `SECRET_MAX_TTL_DAYS` | `30` | Expiry ceiling and default |
| `SECRET_RATE_LIMIT_PER_HOUR` | `20` | Creations per IP per hour |

## Development

```bash
uv sync
uv run pytest
uv run uvicorn app.main:app --port 8001 --reload
```

`node verify_crypto.mjs` cross-checks that the browser crypto (AES key + passphrase verifier)
matches the Python side. `bash e2e_check.sh` spins up a local instance and smoke-tests pages,
headers and the full secret flow, including the passphrase gate (`gate_e2e.py`).

## Deployment (systemd --user)

```bash
# on the server, as the service user
git clone https://github.com/cynderlab/secret.cynderlab.com ~/apps/secret.cynderlab.com
cd ~/apps/secret.cynderlab.com
cp .env.example .env && $EDITOR .env
uv sync --no-dev

mkdir -p ~/.config/systemd/user
cp deploy/secret-cynderlab.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now secret-cynderlab.service
loginctl enable-linger "$USER"      # keep user services running after logout
```

DB migrations run automatically in `ExecStartPre` on every (re)start. The app itself sweeps
expired secrets (at startup and hourly) and VACUUMs the database — no cron or timer needed.
Upgrading from a version that shipped `secret-cynderlab-cleanup.timer`? Remove it:
`systemctl --user disable --now secret-cynderlab-cleanup.timer` and delete both cleanup
units from `~/.config/systemd/user/`.

Upgrades: `git pull && uv sync --no-dev && systemctl --user restart secret-cynderlab.service`.

nginx origin config: `deploy/nginx-secret.cynderlab.com.conf` (Cloudflare in front; the app
must run with exactly **one** worker — the rate limiter is in-process).

## License

MIT — see [LICENSE](LICENSE). Built and operated by CYNDERLAB DIGITAL SL ·
[hola@cynderlab.com](mailto:hola@cynderlab.com)
