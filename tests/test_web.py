def test_home_renders(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "burn" in r.text.lower()
    for element_id in ("secret-input", "expiry-input", "passphrase-input",
                      "create-btn", "result-panel"):
        assert f'id="{element_id}"' in r.text


def test_footer_links(client):
    r = client.get("/")
    for href in ("https://github.com/cynderlab/secret.cynderlab.com", "/privacy", "/legal",
                 "https://cynderlab.com"):
        assert href in r.text
    assert "CYNDERLAB DIGITAL SL" in r.text


def test_static_assets_served(client):
    assert client.get("/static/css/app.css").status_code == 200
    assert client.get("/static/js/crypto.js").status_code == 200
    assert client.get("/static/js/create.js").status_code == 200
    assert client.get("/static/img/logo.png").status_code == 200


def test_reveal_page_renders_shell(client):
    slug = "A" * 22
    r = client.get(f"/s/{slug}")
    assert r.status_code == 200
    assert f'data-slug="{slug}"' in r.text
    assert 'id="reveal-btn"' in r.text


def test_reveal_page_never_contains_secret_data(client):
    body = client.post("/api/secrets", json={"secret": "topsecret123"}).json()
    r = client.get(f"/s/{body['slug']}")
    assert "topsecret123" not in r.text          # shell only; JS fetches ciphertext on click


def test_reveal_page_invalid_slug_404(client):
    assert client.get("/s/short").status_code == 404
