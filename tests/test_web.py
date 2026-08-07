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
