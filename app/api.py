import base64
import sqlite3
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidTag
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
            410,
            "wrong key or passphrase — the secret was consumed by this attempt and is now burned")
    return {"secret": plaintext.decode("utf-8")}
