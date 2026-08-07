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
uv run uvicorn app.main:app --port 8001 --reload
```

Configuration is env-driven; see `.env.example`. `verify_crypto.mjs` (run with `node`)
cross-checks that the browser crypto in `static/js/crypto.js` matches `app/crypto.py`.

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

MIT — see [LICENSE](LICENSE).
