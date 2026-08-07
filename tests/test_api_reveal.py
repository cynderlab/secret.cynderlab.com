from app import crypto


def make(client, secret="s3cret", passphrase=None):
    payload = {"secret": secret}
    if passphrase:
        payload["passphrase"] = passphrase
    body = client.post("/api/secrets", json=payload).json()
    key = body["link"].split("#", 1)[1]
    return body["slug"], key


def test_meta_reports_without_burning(client):
    slug, _ = make(client, passphrase="pw")
    for _ in range(2):
        r = client.get(f"/api/secrets/{slug}")
        assert r.status_code == 200
        assert r.json()["has_passphrase"] is True


def test_meta_404_for_unknown(client):
    assert client.get("/api/secrets/" + "x" * 22).status_code == 404


def test_reveal_roundtrip_and_burn(client):
    slug, key = make(client, secret="deploy: tk-42")
    r = client.post(f"/api/secrets/{slug}/reveal", json={"key": key})
    assert r.status_code == 200
    assert r.json()["secret"] == "deploy: tk-42"
    assert client.post(f"/api/secrets/{slug}/reveal", json={"key": key}).status_code == 404
    assert client.get(f"/api/secrets/{slug}").status_code == 404


def test_reveal_with_passphrase(client):
    slug, key = make(client, passphrase="correct horse")
    r = client.post(f"/api/secrets/{slug}/reveal",
                    json={"key": key, "passphrase": "correct horse"})
    assert r.status_code == 200
    assert r.json()["secret"] == "s3cret"


def test_wrong_key_burns_and_returns_410(client):
    slug, key = make(client)
    bad = crypto.b64u_encode(crypto.new_key())
    r = client.post(f"/api/secrets/{slug}/reveal", json={"key": bad})
    assert r.status_code == 410
    assert "burned" in r.json()["detail"].lower()
    assert client.get(f"/api/secrets/{slug}").status_code == 404  # gone for real


def test_consume_returns_ciphertext_and_burns(client):
    slug, key = make(client, secret="webflow")
    r = client.post(f"/api/secrets/{slug}/consume")
    assert r.status_code == 200
    body = r.json()
    aes_key = crypto.derive_key(crypto.b64u_decode(key), slug, None)
    plaintext = crypto.decrypt(
        crypto.b64u_decode(body["nonce"]), crypto.b64u_decode(body["ciphertext"]),
        aes_key, slug)
    assert plaintext == b"webflow"
    assert client.post(f"/api/secrets/{slug}/consume").status_code == 404
