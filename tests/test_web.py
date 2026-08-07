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
    assert client.get("/static/img/og.png").status_code == 200


def test_social_card_metadata(client):
    r = client.get("/")
    assert 'property="og:title"' in r.text
    assert 'content="https://secret.test/static/img/og.png"' in r.text
    assert 'content="https://secret.test/"' in r.text          # og:url
    assert 'name="twitter:card" content="summary_large_image"' in r.text


def test_secret_page_social_card_override(client):
    body = client.post("/api/secrets", json={"secret": "x"}).json()
    r = client.get(f"/s/{body['slug']}")
    assert "Someone sent you a secret" in r.text                # og:title for shared links
    assert "read exactly once" in r.text


def test_reveal_page_renders_shell(client):
    body = client.post("/api/secrets", json={"secret": "x"}).json()
    r = client.get(f"/s/{body['slug']}")
    assert r.status_code == 200
    assert f'data-slug="{body["slug"]}"' in r.text
    assert 'id="reveal-btn"' in r.text


def test_reveal_page_never_contains_secret_data(client):
    body = client.post("/api/secrets", json={"secret": "topsecret123"}).json()
    r = client.get(f"/s/{body['slug']}")
    assert "topsecret123" not in r.text          # shell only; JS fetches ciphertext on click


def test_reveal_page_invalid_slug_404(client):
    assert client.get("/s/short").status_code == 404


def test_reveal_page_unknown_or_expired_slug_is_branded_404(client):
    r = client.get("/s/" + "A" * 22)             # well-formed slug, no such secret
    assert r.status_code == 404
    assert "CYNDERLAB DIGITAL SL" in r.text      # branded 404 page, not the reveal shell
    assert 'id="reveal-btn"' not in r.text


def test_home_is_clean_of_explanations(client):
    r = client.get("/")
    assert 'id="tab-human"' not in r.text        # explanation moved to its own page
    assert 'id="create-form"' in r.text          # the form stays
    assert '/how-it-works' in r.text             # header links to the new page


def test_how_it_works_page_with_dual_toggle(client):
    r = client.get("/how-it-works")
    assert r.status_code == 200
    for element_id in ("tab-human", "tab-agent", "how-it-works", "agents"):
        assert f'id="{element_id}"' in r.text
    assert "whoami" in r.text
    assert "curl" in r.text                      # machine panel travelled with it


def test_security_headers_on_every_response(client):
    r = client.get("/")
    csp = r.headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"


def test_no_store_on_sensitive_paths(client):
    assert client.get("/s/" + "A" * 22).headers["cache-control"] == "no-store"
    assert client.get("/api/secrets/" + "A" * 22).headers["cache-control"] == "no-store"
    assert "no-store" not in client.get("/").headers.get("cache-control", "")


def test_html_404_is_branded(client):
    r = client.get("/does-not-exist")
    assert r.status_code == 404
    assert "CYNDERLAB DIGITAL SL" in r.text       # base template rendered
    assert "text/html" in r.headers["content-type"]


def test_404_page_has_glitch_terminal_show(client):
    r = client.get("/does-not-exist")
    assert 'class="glitch mono"' in r.text        # animated 404 headline
    assert 'id="e404-terminal"' in r.text         # typed forensics session
    assert 'cd ~' in r.text                       # the way home
    assert "/static/js/e404.js" in r.text


def test_other_errors_keep_plain_layout(client):
    r = client.post("/privacy")                   # 405 method not allowed
    assert r.status_code == 405
    assert 'id="e404-terminal"' not in r.text


def test_api_404_stays_json(client):
    r = client.get("/api/secrets/" + "A" * 22)
    assert "application/json" in r.headers["content-type"]
    assert "detail" in r.json()


def test_robots_txt(client):
    r = client.get("/robots.txt")
    assert r.status_code == 200
    assert "Disallow: /s/" in r.text
    assert "Disallow: /api/" in r.text


def test_llms_txt_documents_api(client):
    r = client.get("/llms.txt")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]
    for fragment in ("POST https://secret.test/api/secrets", "/reveal", "/consume",
                     "one read"):
        assert fragment in r.text


def test_privacy_and_legal_pages(client):
    p = client.get("/privacy")
    assert p.status_code == 200 and "CYNDERLAB DIGITAL SL" in p.text
    l = client.get("/legal")
    assert l.status_code == 200 and "B27584010" in l.text
