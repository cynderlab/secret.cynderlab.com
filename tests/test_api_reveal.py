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


def consume(client, slug, passphrase=None):
    body = {}
    if passphrase is not None:
        body["verifier"] = crypto.b64u_encode(crypto.derive_verifier(passphrase, slug))
    return client.post(f"/api/secrets/{slug}/consume", json=body)


def test_gated_consume_with_correct_passphrase_burns_and_decrypts(client):
    slug, key = make_secret(client, secret=b"top", passphrase="correct horse")
    r = consume(client, slug, "correct horse")
    assert r.status_code == 200
    body = r.json()
    aes = crypto.derive_key(crypto.b64u_decode(key), slug, "correct horse")
    assert crypto.decrypt(crypto.b64u_decode(body["nonce"]),
                          crypto.b64u_decode(body["ciphertext"]), aes, slug) == b"top"
    assert consume(client, slug, "correct horse").status_code == 404   # burned


def test_gated_consume_wrong_passphrase_does_not_burn(client):
    slug, _ = make_secret(client, passphrase="right")
    r = consume(client, slug, "wrong")
    assert r.status_code == 403
    assert r.json()["attempts_left"] == 4
    assert client.get(f"/api/secrets/{slug}").status_code == 200       # still alive
    r = consume(client, slug)                                          # missing verifier
    assert r.status_code == 403
    assert r.json()["attempts_left"] == 3


def test_gated_consume_locks_after_five_failures(client):
    slug, _ = make_secret(client, passphrase="right")
    for expected in (4, 3, 2, 1):
        assert consume(client, slug, "wrong").json()["attempts_left"] == expected
    r = consume(client, slug, "wrong")                                 # 5th failure
    assert r.status_code == 429
    assert r.json()["locked_seconds"] > 0
    assert "retry-after" in {k.lower() for k in r.headers}
    # even the CORRECT passphrase is rejected while locked, and nothing burns
    assert consume(client, slug, "right").status_code == 429
    assert client.get(f"/api/secrets/{slug}").status_code == 200


def test_gated_consume_works_after_lock_expires(client):
    slug, _ = make_secret(client, passphrase="right")
    for _ in range(5):
        consume(client, slug, "wrong")
    # simulate the 5 minutes passing
    client.app.state.db.execute(
        "UPDATE secrets SET locked_until = '2000-01-01T00:00:00Z' WHERE slug = ?", (slug,))
    client.app.state.db.commit()
    assert consume(client, slug, "right").status_code == 200


def test_create_gated_requires_verifier(client):
    slug = crypto.new_slug()
    aes = crypto.derive_key(crypto.new_key(), slug, "pw")
    nonce, ct = crypto.encrypt(b"x", aes, slug)
    r = client.post("/api/secrets/encrypted", json={
        "slug": slug, "ciphertext": crypto.b64u_encode(ct),
        "nonce": crypto.b64u_encode(nonce), "has_passphrase": True})
    assert r.status_code == 422
