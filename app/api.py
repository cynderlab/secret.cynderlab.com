"""Transport for the browser UI. The server never touches plaintext or keys:
secrets arrive already encrypted (WebCrypto in the client) and leave still
encrypted — decryption happens in the recipient's browser."""

import base64
import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from . import crypto, store
from .config import Settings
from .ratelimit import client_ip

router = APIRouter(prefix="/api")


def enforce_create_limit(request: Request) -> None:
    retry_after = request.app.state.limiter.check(client_ip(request))
    if retry_after is not None:
        raise HTTPException(429, "rate limit exceeded: try again later",
                            headers={"Retry-After": str(retry_after)})


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


@router.post("/secrets/encrypted", status_code=201)
def create_secret_encrypted(body: CreateEncrypted, request: Request):
    enforce_create_limit(request)
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
