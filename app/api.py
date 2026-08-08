"""Transport for the browser UI. The server never touches plaintext or keys:
secrets arrive already encrypted (WebCrypto in the client) and leave still
encrypted — decryption happens in the recipient's browser."""

import base64
import hashlib
import hmac
import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from . import crypto, store
from .config import Settings
from .ratelimit import client_ip

router = APIRouter(prefix="/api")


def enforce_create_limit(request: Request) -> None:
    retry_after = request.app.state.limiter.check(client_ip(request))
    if retry_after is not None:
        raise HTTPException(429, "rate limit exceeded: try again later",
                            headers={"Retry-After": str(retry_after)})


# Don't trust, verify: every client-supplied value is bounded and checked here,
# regardless of what the UI enforces. Unknown fields are rejected outright.
class CreateEncrypted(BaseModel):
    model_config = ConfigDict(extra="forbid")

    slug: str = Field(min_length=22, max_length=22)
    ciphertext: str = Field(min_length=23, max_length=360_000)   # b64u(tag+1B .. 256KB+tag)
    nonce: str = Field(min_length=16, max_length=16)             # b64u of exactly 12 bytes
    has_passphrase: bool = False
    verifier: str | None = Field(default=None, min_length=43, max_length=43)
    expires_at: str | None = Field(default=None, min_length=10, max_length=20)


class ConsumeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verifier: str | None = Field(default=None, min_length=43, max_length=43)


def parse_expiry(raw: str | None, default_ttl_days: int, max_ttl_days: int) -> str:
    now = store.utcnow()
    latest = now + timedelta(days=max_ttl_days)
    if raw is None:
        return store.iso(now + timedelta(days=default_ttl_days))
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
    if len(nonce) != 12:
        raise HTTPException(422, "nonce must decode to exactly 12 bytes")
    if len(ciphertext) < 17:  # GCM tag (16) + at least one byte of content
        raise HTTPException(422, "ciphertext is too short to be a valid encrypted secret")
    if len(ciphertext) > settings.max_secret_bytes + 16:
        raise HTTPException(413, f"ciphertext exceeds {settings.max_secret_bytes} bytes")
    verifier_hash = None
    if body.has_passphrase:
        if not body.verifier:
            raise HTTPException(422, "has_passphrase requires a verifier")
        verifier = _b64u_or_422("verifier", body.verifier)
        if len(verifier) != 32:
            raise HTTPException(422, "verifier must decode to 32 bytes")
        verifier_hash = hashlib.sha256(verifier).digest()
    elif body.verifier is not None:
        raise HTTPException(422, "verifier without has_passphrase makes no sense")
    try:
        expires_at = parse_expiry(body.expires_at, settings.default_ttl_days,
                                  settings.max_ttl_days)
    except ValueError as e:
        raise HTTPException(422, str(e))
    try:
        store.create_secret(conn, body.slug, ciphertext, nonce, body.has_passphrase,
                            expires_at, verifier_hash=verifier_hash)
    except sqlite3.IntegrityError:
        raise HTTPException(409, "slug already exists, generate a new one")
    return {"slug": body.slug, "expires_at": expires_at}


@router.get("/secrets/{slug}")
def secret_meta(slug: str, request: Request):
    if not crypto.SLUG_RE.fullmatch(slug):
        raise HTTPException(404, "secret not found: never existed, expired, or already read")
    row = store.get_meta(request.app.state.db, slug)
    if row is None:
        raise HTTPException(404, "secret not found: never existed, expired, or already read")
    return {"slug": slug, "has_passphrase": bool(row["has_passphrase"]),
            "expires_at": row["expires_at"]}


@router.post("/secrets/{slug}/consume")
def consume(slug: str, request: Request, body: ConsumeRequest | None = None):
    if not crypto.SLUG_RE.fullmatch(slug):
        raise HTTPException(404, "secret not found: never existed, expired, or already read")
    conn = request.app.state.db
    auth = store.get_auth(conn, slug)
    if auth is None:
        raise HTTPException(404, "secret not found: never existed, expired, or already read")

    if auth["locked_until"] is not None and auth["locked_until"] > store.iso(store.utcnow()):
        locked_for = _seconds_until(auth["locked_until"])
        return JSONResponse(
            {"detail": "too many failed attempts — secret temporarily locked",
             "locked_seconds": locked_for},
            status_code=429, headers={"Retry-After": str(locked_for)})

    if auth["verifier_hash"] is not None:
        supplied = None
        if body and body.verifier:
            supplied = _b64u_or_422("verifier", body.verifier)
        if supplied is None or not hmac.compare_digest(
                hashlib.sha256(supplied).digest(), auth["verifier_hash"]):
            outcome = store.register_failure(conn, slug)
            if outcome == "locked":
                locked_for = store.LOCK_MINUTES * 60
                return JSONResponse(
                    {"detail": "too many failed attempts — secret locked for 5 minutes",
                     "locked_seconds": locked_for},
                    status_code=429, headers={"Retry-After": str(locked_for)})
            return JSONResponse({"detail": "wrong passphrase", "attempts_left": outcome},
                                status_code=403)

    row = store.consume_secret(conn, slug)
    if row is None:
        raise HTTPException(404, "secret not found: never existed, expired, or already read")
    return {"ciphertext": crypto.b64u_encode(row["ciphertext"]),
            "nonce": crypto.b64u_encode(row["nonce"]),
            "has_passphrase": bool(row["has_passphrase"])}


def _seconds_until(iso_ts: str) -> int:
    dt = datetime.strptime(iso_ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return max(1, int((dt - store.utcnow()).total_seconds()))
