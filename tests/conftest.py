import pytest
from fastapi.testclient import TestClient

from app import crypto
from app.config import Settings
from app.main import create_app


def make_secret(client, secret=b"s3cret", passphrase=None, expires_at=None):
    """Create a secret the way the browser does (client-side encryption).

    Returns (slug, key_b64u) so tests can build links or decrypt consumes.
    """
    slug, link_key = crypto.new_slug(), crypto.new_key()
    aes_key = crypto.derive_key(link_key, slug, passphrase)
    nonce, ciphertext = crypto.encrypt(secret, aes_key, slug)
    payload = {
        "slug": slug,
        "ciphertext": crypto.b64u_encode(ciphertext),
        "nonce": crypto.b64u_encode(nonce),
        "has_passphrase": passphrase is not None,
        "expires_at": expires_at,
    }
    if passphrase is not None:
        payload["verifier"] = crypto.b64u_encode(crypto.derive_verifier(passphrase, slug))
    r = client.post("/api/secrets/encrypted", json=payload)
    assert r.status_code == 201, r.text
    return slug, crypto.b64u_encode(link_key)


def make_settings(tmp_path, **overrides) -> Settings:
    defaults = dict(
        db_path=str(tmp_path / "test.db"),
        base_url="https://secret.test",
        max_secret_bytes=262144,
        default_ttl_days=3,
        max_ttl_days=30,
        rate_limit_per_hour=1000,     # effectively off; rate-limit tests override this
    )
    defaults.update(overrides)
    return Settings(**defaults)


@pytest.fixture
def client(tmp_path):
    app = create_app(make_settings(tmp_path))
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
