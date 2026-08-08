from app import crypto


def encrypted_payload(secret=b"hello", slug=None):
    slug = slug or crypto.new_slug()
    link_key = crypto.new_key()
    aes_key = crypto.derive_key(link_key, slug, None)
    nonce, ct = crypto.encrypt(secret, aes_key, slug)
    return {"slug": slug, "ciphertext": crypto.b64u_encode(ct),
            "nonce": crypto.b64u_encode(nonce)}


def test_create_encrypted(client):
    payload = encrypted_payload()
    r = client.post("/api/secrets/encrypted", json=payload)
    assert r.status_code == 201
    body = r.json()
    assert body["slug"] == payload["slug"]
    assert body["expires_at"].endswith("Z")


def test_create_rejects_oversize_ciphertext(client):
    payload = encrypted_payload(secret=b"x" * 262200)
    r = client.post("/api/secrets/encrypted", json=payload)
    assert r.status_code == 413


def test_create_rejects_past_expiry(client):
    r = client.post("/api/secrets/encrypted",
                    json={**encrypted_payload(), "expires_at": "2001-01-01"})
    assert r.status_code == 422


def test_create_rejects_expiry_beyond_max(client):
    r = client.post("/api/secrets/encrypted",
                    json={**encrypted_payload(), "expires_at": "2999-01-01"})
    assert r.status_code == 422


def test_create_without_date_self_destructs_in_default_days(client):
    from datetime import datetime, timezone

    r = client.post("/api/secrets/encrypted", json=encrypted_payload())
    assert r.status_code == 201
    expires = datetime.strptime(r.json()["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc)
    delta_days = (expires - datetime.now(timezone.utc)).total_seconds() / 86400
    assert 2.9 < delta_days <= 3.01              # default is 3 days, max is 30


def test_create_accepts_valid_expiry_date(client):
    r = client.post("/api/secrets/encrypted",
                    json={**encrypted_payload(), "expires_at": "2026-08-20"})
    assert r.status_code == 201
    assert r.json()["expires_at"] == "2026-08-20T23:59:59Z"


def test_create_duplicate_slug_conflicts(client):
    payload = encrypted_payload()
    assert client.post("/api/secrets/encrypted", json=payload).status_code == 201
    assert client.post("/api/secrets/encrypted", json=payload).status_code == 409


def test_create_rejects_bad_slug(client):
    r = client.post("/api/secrets/encrypted", json={
        "slug": "../etc/passwd", "ciphertext": "YQ", "nonce": "YQ"})
    assert r.status_code == 422


def test_create_rejects_garbage_expiry(client):
    for bad in ("not-a-date", "2026-13-45", "2026-08-20T99:99:99Z", "20260820"):
        r = client.post("/api/secrets/encrypted",
                        json={**encrypted_payload(), "expires_at": bad})
        assert r.status_code == 422, bad


def test_create_rejects_wrong_nonce_length(client):
    from app import crypto
    payload = encrypted_payload()
    payload["nonce"] = crypto.b64u_encode(b"short")        # not 12 bytes
    assert client.post("/api/secrets/encrypted", json=payload).status_code == 422


def test_create_rejects_impossible_ciphertext(client):
    payload = encrypted_payload()
    payload["ciphertext"] = crypto.b64u_encode(b"tiny")    # smaller than a GCM tag
    assert client.post("/api/secrets/encrypted", json=payload).status_code == 422


def test_create_rejects_verifier_without_passphrase(client):
    payload = encrypted_payload()
    payload["verifier"] = crypto.b64u_encode(b"v" * 32)
    payload["has_passphrase"] = False
    assert client.post("/api/secrets/encrypted", json=payload).status_code == 422


def test_create_rejects_unknown_fields(client):
    payload = {**encrypted_payload(), "evil_extra": "field"}
    assert client.post("/api/secrets/encrypted", json=payload).status_code == 422


def test_create_rejects_oversized_body_before_parsing(client):
    huge = "x" * 600_000                                   # > body cap, junk on purpose
    r = client.post("/api/secrets/encrypted",
                    content='{"slug": "' + huge + '"}',
                    headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_meta_and_consume_reject_malformed_slugs(client):
    for slug in ("short", "x" * 23, "in%76alid+slug!!!!!!!!"):
        assert client.get(f"/api/secrets/{slug}").status_code == 404
        assert client.post(f"/api/secrets/{slug}/consume").status_code == 404


def test_server_side_plaintext_endpoints_are_gone(client):
    assert client.post("/api/secrets", json={"secret": "x"}).status_code in (404, 405)
    slug = crypto.new_slug()
    r = client.post(f"/api/secrets/{slug}/reveal", json={"key": "x"})
    assert r.status_code in (404, 405)
