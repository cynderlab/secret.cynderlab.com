import hashlib
from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from .crypto import SLUG_RE
from .i18n import make_t, negotiate
from .store import get_meta

BASE_DIR = Path(__file__).resolve().parent.parent


def _i18n_context(request: Request) -> dict:
    lang = negotiate(request.headers.get("accept-language"))
    return {"lang": lang, "t": make_t(lang)}


templates = Jinja2Templates(directory=str(BASE_DIR / "templates"),
                            context_processors=[_i18n_context])
router = APIRouter()


@lru_cache(maxsize=None)
def _asset_hash(rel_path: str) -> str:
    return hashlib.sha256((BASE_DIR / "static" / rel_path).read_bytes()).hexdigest()[:8]


def static_url(rel_path: str) -> str:
    """Content-hashed static URL: cache busts exactly when the file changes."""
    try:
        return f"/static/{rel_path}?v={_asset_hash(rel_path)}"
    except OSError:
        return f"/static/{rel_path}"


templates.env.globals["static_url"] = static_url


@router.get("/", response_class=HTMLResponse)
def home(request: Request):
    settings = request.app.state.settings
    return templates.TemplateResponse(request, "home.html", {
        "max_ttl_days": settings.max_ttl_days,
        "max_kb": settings.max_secret_bytes // 1024,
    })


@router.get("/how-it-works", response_class=HTMLResponse)
def how_it_works(request: Request):
    return templates.TemplateResponse(request, "how-it-works.html", {})


@router.get("/s/{slug}", response_class=HTMLResponse)
def reveal_page(slug: str, request: Request):
    if not SLUG_RE.fullmatch(slug):
        raise HTTPException(404)
    if get_meta(request.app.state.db, slug) is None:
        # burned, expired or never existed — same branded 404 for all of them
        raise HTTPException(404)
    return templates.TemplateResponse(request, "secret.html", {"slug": slug})


@router.get("/robots.txt", response_class=PlainTextResponse)
def robots():
    return "User-agent: *\nDisallow: /s/\nDisallow: /api/\nAllow: /\n"


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
POST {base}/api/secrets/<slug>/consume does the reverse (burns, returns ciphertext).

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
    lang = negotiate(request.headers.get("accept-language"))
    return templates.TemplateResponse(request, f"privacy-{lang}.html", {})


@router.get("/legal", response_class=HTMLResponse)
def legal(request: Request):
    lang = negotiate(request.headers.get("accept-language"))
    return templates.TemplateResponse(request, f"legal-{lang}.html", {})
