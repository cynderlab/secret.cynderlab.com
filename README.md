# secret.cynderlab.com

One-time secret sharing by [Cynderlab](https://cynderlab.com). Paste a secret, get a link,
first read burns it. The decryption key lives only in the link — the server stores an
AES-256-GCM blob it cannot decrypt.

**Live at [secret.cynderlab.com](https://secret.cynderlab.com)** · API docs for agents at
[`/llms.txt`](https://secret.cynderlab.com/llms.txt)

## Features

- **Burn on read** — every secret allows exactly one read (atomic `DELETE … RETURNING`);
  a second visit lands on a 404.
- **Key in the URL, never on the server** — a stolen database is a pile of undecryptable blobs.
- **Zero-knowledge web flow** — the browser encrypts with WebCrypto; the key travels in the
  URL fragment (`#`), which browsers never send to any server.
- **Agent-friendly API** — plain JSON over `curl`; the machine-readable contract lives at
  `/llms.txt`, and the home page explains the flow for humans and machines alike.
- **Optional expiry** — calendar picker, 30-day maximum; expired secrets are never served and
  are swept hourly.
- **Optional passphrase** — a second factor mixed into the key derivation, never stored.
- **Abuse control** — 20 secret creations/hour/IP (in-memory sliding window), 256 KB max.
- **Nothing to leak** — no accounts, no cookies, no analytics, no third-party requests, no IPs
  in the database. Strict CSP, `no-store` on sensitive paths, branded error pages.

## Security model, in one paragraph

The web UI encrypts in your browser (WebCrypto); the key rides in the URL fragment (`#`),
which browsers never transmit. The API path encrypts/decrypts in server memory only (key in
POST bodies, never stored, never logged). Every secret is destroyed on first read and expires
after at most 30 days. The database holds no keys, no plaintext, no IPs. Broken links —
missing key, expired, already read — all resolve to the same 404.

### Crypto scheme (`cynderlab.secret.v1`)

```
aes_key = HKDF-SHA256(
    ikm  = link_key (32 random bytes, lives only in the URL),
    salt = passphrase ? PBKDF2-HMAC-SHA256(passphrase, salt=utf8(slug), 310000 iters) : empty,
    info = "cynderlab.secret.v1")
AES-256-GCM · 12-byte nonce · AAD = utf8(slug)
```

Implemented twice — `app/crypto.py` (server) and `static/js/crypto.js` (browser) — and locked
together by a pinned test vector (`tests/test_crypto.py`) plus `verify_crypto.mjs`, a Node
script that encrypts in JS and decrypts in Python.

## API in 30 seconds

```bash
# create (server encrypts in memory; the key is returned once, inside the link)
curl -s https://secret.cynderlab.com/api/secrets \
  -H 'content-type: application/json' \
  -d '{"secret": "the payload", "expires_at": "2026-09-01"}'
# -> {"slug": "...", "link": "https://secret.cynderlab.com/s/<slug>#<key>", ...}

# reveal (burns it; key = the part after '#')
curl -s https://secret.cynderlab.com/api/secrets/<slug>/reveal \
  -H 'content-type: application/json' -d '{"key": "<key>"}'
```

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/secrets` | POST | Create (server-side encryption, in memory only) |
| `/api/secrets/encrypted` | POST | Create from a pre-encrypted blob (what the web UI does) |
| `/api/secrets/{slug}` | GET | Metadata check — does **not** burn |
| `/api/secrets/{slug}/consume` | POST | Burn and return the ciphertext (browser decrypts) |
| `/api/secrets/{slug}/reveal` | POST | Burn and return the plaintext (server decrypts) |

A reveal with a wrong key or passphrase still burns the secret (HTTP 410) — no oracle, no
retries, by design. Full contract: [`/llms.txt`](https://secret.cynderlab.com/llms.txt).

## Stack

FastAPI · SQLite (stdlib `sqlite3`, WAL, no ORM) · Jinja2 · vanilla JS + WebCrypto ·
`cryptography` · uv · pytest. One process, one worker, no external services.

```
app/            config, db + migrations runner, crypto, store, api, web, ratelimit, cleanup
migrations/     numbered .sql files, applied by `python -m app.migrate` (ExecStartPre)
templates/      Jinja2 pages (home, how-it-works, reveal, legal, errors)
static/         css, fonts (self-hosted), crypto.js/create.js/reveal.js/tabs.js
deploy/         systemd user units + cleanup timer + nginx origin config
tests/          48 tests: crypto vectors, burn semantics, api, rate limit, headers, pages
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

`node verify_crypto.mjs` cross-checks that the browser crypto matches the Python side.
`bash e2e_check.sh` runs a live end-to-end smoke test against a local uvicorn.

## Deployment (systemd --user)

```bash
# on the server, as the service user
git clone https://github.com/cynderlab/secret.cynderlab.com ~/apps/secret.cynderlab.com
cd ~/apps/secret.cynderlab.com
cp .env.example .env && $EDITOR .env
uv sync --no-dev

mkdir -p ~/.config/systemd/user
cp deploy/secret-cynderlab.service deploy/secret-cynderlab-cleanup.service \
   deploy/secret-cynderlab-cleanup.timer ~/.config/systemd/user/
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

MIT — see [LICENSE](LICENSE). Built and operated by CYNDERLAB DIGITAL SL ·
[hola@cynderlab.com](mailto:hola@cynderlab.com)
