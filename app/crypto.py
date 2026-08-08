"""Scheme cynderlab.secret.v1 — Python mirror of static/js/crypto.js.

The production server never encrypts or decrypts: all real cryptography runs
in the browser. This mirror exists so the test suite (and gate_e2e.py) can act
as a browser, and so the shared test vectors keep both implementations locked
together. The `cryptography` package is therefore a dev-only dependency and is
imported lazily — the runtime only ever touches the stdlib helpers below.
"""

import base64
import re
import secrets

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


def derive_verifier(passphrase: str, slug: str) -> bytes:
    """Proof-of-passphrase sent to the server. Domain-separated from the AES key
    derivation by the '.verify' salt suffix; the server stores only its sha256."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=f"{slug}.verify".encode("utf-8"),
        iterations=PBKDF2_ITERATIONS,
    ).derive(passphrase.encode("utf-8"))


def derive_key(link_key: bytes, slug: str, passphrase: str | None) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, slug.encode("utf-8"))
    return nonce, ciphertext


def decrypt(nonce: bytes, ciphertext: bytes, aes_key: bytes, slug: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(aes_key).decrypt(nonce, ciphertext, slug.encode("utf-8"))
