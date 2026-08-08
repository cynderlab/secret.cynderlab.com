def test_home_renders(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "burn" in r.text.lower()
    for element_id in ("secret-input", "expiry-input", "passphrase-input",
                      "create-btn", "result-panel"):
        assert f'id="{element_id}"' in r.text
    assert 'data-max-ttl="30"' in r.text          # ceiling, JS builds the calendar with it
    assert 'data-default-ttl="3"' in r.text       # prefill value
    assert "self-destructs in 3 days" in r.text   # the expiry copy shows both values
    assert "up to 30" in r.text


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
    assert client.get("/static/js/vendor/qrcode.js").status_code == 200


def test_home_has_qr_slot_for_generated_link(client):
    r = client.get("/")
    assert 'id="result-qr"' in r.text
    assert "/static/js/vendor/qrcode.js" in r.text


def test_result_panel_is_minimal(client):
    r = client.get("/")
    assert 'id="result-link"' in r.text           # truncated, click-to-copy pill
    assert 'id="result-meta"' in r.text           # one condensed info line
    assert 'id="qr-toggle"' in r.text             # QR folded behind a button
    assert 'id="qr-box"' in r.text
    assert 'id="result-expiry"' not in r.text     # old verbose lines are gone
    assert "READS LEFT" not in r.text


def test_static_urls_are_content_versioned(client):
    r = client.get("/")
    assert "/static/css/app.css?v=" in r.text
    assert "/static/js/crypto.js?v=" in r.text
    assert "/static/img/logo.png?v=" in r.text


def test_static_responses_are_long_cached_and_immutable(client):
    r = client.get("/static/css/app.css")
    assert "immutable" in r.headers["cache-control"]
    assert "max-age=31536000" in r.headers["cache-control"]
    # html pages must NOT get the long cache
    assert "immutable" not in client.get("/").headers.get("cache-control", "")


def test_social_card_metadata(client):
    r = client.get("/")
    assert 'property="og:title"' in r.text
    assert 'content="https://secret.test/static/img/og.png?v=' in r.text
    assert 'content="https://secret.test/"' in r.text          # og:url
    assert 'name="twitter:card" content="summary_large_image"' in r.text


def test_secret_page_social_card_override(client):
    from conftest import make_secret
    slug, _ = make_secret(client)
    r = client.get(f"/s/{slug}")
    assert "Someone sent you a secret" in r.text                # og:title for shared links
    assert "read exactly once" in r.text


def test_reveal_page_renders_shell(client):
    from conftest import make_secret
    slug, _ = make_secret(client)
    r = client.get(f"/s/{slug}")
    assert r.status_code == 200
    assert f'data-slug="{slug}"' in r.text
    assert 'id="reveal-btn"' in r.text


def test_reveal_page_never_contains_secret_data(client):
    from conftest import make_secret
    slug, _ = make_secret(client, secret=b"topsecret123")
    r = client.get(f"/s/{slug}")
    assert "topsecret123" not in r.text          # shell only; JS fetches ciphertext on click


def test_reveal_page_invalid_slug_404(client):
    assert client.get("/s/short").status_code == 404


def test_reveal_page_unknown_or_expired_slug_is_branded_404(client):
    r = client.get("/s/" + "A" * 22)             # well-formed slug, no such secret
    assert r.status_code == 404
    assert "CYNDERLAB DIGITAL SL" in r.text      # branded 404 page, not the reveal shell
    assert 'id="reveal-btn"' not in r.text


def test_header_has_share_cta(client):
    r = client.get("/how-it-works")
    assert 'class="cta-btn"' in r.text
    assert 'href="/#create-form"' in r.text
    assert "Share a secret" in r.text
    ca = client.get("/", headers={"accept-language": "ca"})
    assert "Comparteix un secret" in ca.text


def test_home_is_clean_of_explanations(client):
    r = client.get("/")
    assert 'id="tab-human"' not in r.text        # explanation moved to its own page
    assert 'id="create-form"' in r.text          # the form stays
    assert '/how-it-works' in r.text             # header links to the new page


def test_how_it_works_page_is_humans_only(client):
    r = client.get("/how-it-works")
    assert r.status_code == 200
    assert "AES-256-GCM" in r.text               # the three steps are there
    assert "tab-agent" not in r.text             # machine tab removed
    assert "curl" not in r.text                  # agents quickstart removed


def test_how_it_works_has_diagram_and_audit_links(client):
    r = client.get("/how-it-works")
    assert 'class="terminal diagram"' in r.text  # ascii flow schema
    base = "https://github.com/cynderlab/secret.cynderlab.com/blob/main/"
    for path in ("static/js/crypto.js", "static/js/create.js", "static/js/reveal.js",
                 "app/store.py", "app/crypto.py"):
        assert base + path in r.text
    ca = client.get("/how-it-works", headers={"accept-language": "ca"})
    assert "mai veu claus" in ca.text            # translated diagram


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


def test_404_page_is_a_friendly_card(client):
    r = client.get("/does-not-exist")
    assert "e404-card" in r.text                  # single tidy card
    assert 'class="vanish mono"' in r.text        # link-turning-to-ash animation
    assert 'cd ~' in r.text                       # the way home
    assert "glitch" not in r.text                 # the old heavy layout is gone
    assert "e404-terminal" not in r.text


def test_other_errors_keep_plain_layout(client):
    r = client.post("/privacy")                   # 405 method not allowed
    assert r.status_code == 405
    assert "e404-card" not in r.text


def test_api_404_stays_json(client):
    r = client.get("/api/secrets/" + "A" * 22)
    assert "application/json" in r.headers["content-type"]
    assert "detail" in r.json()


def test_robots_txt(client):
    r = client.get("/robots.txt")
    assert r.status_code == 200
    assert "Disallow: /s/" in r.text
    assert "Disallow: /api/" in r.text


def test_llms_txt_is_gone(client):
    assert client.get("/llms.txt").status_code == 404


def test_privacy_and_legal_pages(client):
    p = client.get("/privacy")
    assert p.status_code == 200 and "CYNDERLAB DIGITAL SL" in p.text
    l = client.get("/legal")
    assert l.status_code == 200 and "B27584010" in l.text
