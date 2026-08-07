from app import crypto


def test_create_server_side(client):
    r = client.post("/api/secrets", json={"secret": "tok-123"})
    assert r.status_code == 201
    body = r.json()
    assert crypto.SLUG_RE.fullmatch(body["slug"])
    assert body["link"].startswith(f"https://secret.test/s/{body['slug']}#")
    key = body["link"].split("#", 1)[1]
    assert len(crypto.b64u_decode(key)) == 32
    assert body["link_api"] == f"https://secret.test/api/secrets/{body['slug']}/reveal"


def test_create_rejects_oversize(client):
    r = client.post("/api/secrets", json={"secret": "x" * 262145})
    assert r.status_code == 413


def test_create_rejects_past_expiry(client):
    r = client.post("/api/secrets", json={"secret": "x", "expires_at": "2001-01-01"})
    assert r.status_code == 422


def test_create_rejects_expiry_beyond_max(client):
    r = client.post("/api/secrets", json={"secret": "x", "expires_at": "2999-01-01"})
    assert r.status_code == 422


def test_create_encrypted_path(client):
    slug, link_key = crypto.new_slug(), crypto.new_key()
    aes_key = crypto.derive_key(link_key, slug, None)
    nonce, ct = crypto.encrypt(b"hello", aes_key, slug)
    r = client.post("/api/secrets/encrypted", json={
        "slug": slug,
        "ciphertext": crypto.b64u_encode(ct),
        "nonce": crypto.b64u_encode(nonce),
    })
    assert r.status_code == 201
    assert r.json()["slug"] == slug


def test_create_encrypted_duplicate_slug_conflicts(client):
    slug = crypto.new_slug()
    payload = {"slug": slug, "ciphertext": crypto.b64u_encode(b"ct"),
               "nonce": crypto.b64u_encode(b"n" * 12)}
    assert client.post("/api/secrets/encrypted", json=payload).status_code == 201
    assert client.post("/api/secrets/encrypted", json=payload).status_code == 409


def test_create_encrypted_rejects_bad_slug(client):
    r = client.post("/api/secrets/encrypted", json={
        "slug": "../etc/passwd", "ciphertext": "YQ", "nonce": "YQ"})
    assert r.status_code == 422
