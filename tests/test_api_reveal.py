import pytest
from cryptography.exceptions import InvalidTag

from app import crypto
from conftest import make_secret


def test_meta_reports_without_burning(client):
    slug, _ = make_secret(client, passphrase="pw")
    for _ in range(2):
        r = client.get(f"/api/secrets/{slug}")
        assert r.status_code == 200
        assert r.json()["has_passphrase"] is True


def test_meta_404_for_unknown(client):
    assert client.get("/api/secrets/" + "x" * 22).status_code == 404


def test_consume_returns_ciphertext_and_burns(client):
    slug, key = make_secret(client, secret=b"webflow")
    r = client.post(f"/api/secrets/{slug}/consume")
    assert r.status_code == 200
    body = r.json()
    aes_key = crypto.derive_key(crypto.b64u_decode(key), slug, None)
    plaintext = crypto.decrypt(
        crypto.b64u_decode(body["nonce"]), crypto.b64u_decode(body["ciphertext"]),
        aes_key, slug)
    assert plaintext == b"webflow"
    assert client.post(f"/api/secrets/{slug}/consume").status_code == 404
    assert client.get(f"/api/secrets/{slug}").status_code == 404


def test_consume_with_passphrase_decrypts_only_with_it(client):
    slug, key = make_secret(client, secret=b"top", passphrase="correct horse")
    body = client.post(f"/api/secrets/{slug}/consume").json()
    nonce = crypto.b64u_decode(body["nonce"])
    ct = crypto.b64u_decode(body["ciphertext"])
    with pytest.raises(InvalidTag):
        crypto.decrypt(nonce, ct,
                       crypto.derive_key(crypto.b64u_decode(key), slug, "wrong"), slug)
    good = crypto.derive_key(crypto.b64u_decode(key), slug, "correct horse")
    assert crypto.decrypt(nonce, ct, good, slug) == b"top"
