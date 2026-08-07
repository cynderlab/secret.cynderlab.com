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
