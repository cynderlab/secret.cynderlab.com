from app.i18n import negotiate


def test_negotiate_defaults_to_english():
    assert negotiate(None) == "en"
    assert negotiate("") == "en"
    assert negotiate("fr-FR,fr;q=0.9,de;q=0.8") == "en"


def test_negotiate_picks_supported_language():
    assert negotiate("ca-ES,ca;q=0.9,en;q=0.8") == "ca"
    assert negotiate("es-ES,es;q=0.9,en;q=0.5") == "es"
    assert negotiate("en-GB,en;q=0.9") == "en"


def test_negotiate_respects_quality_order():
    assert negotiate("fr;q=0.9,es;q=0.8,en;q=0.2") == "es"
    assert negotiate("ca;q=0.3,es;q=0.9") == "es"


def test_home_negotiates_language(client):
    ca = client.get("/", headers={"accept-language": "ca-ES,ca;q=0.9"})
    assert '<html lang="ca">' in ca.text
    assert "Comparteix secrets que" in ca.text
    es = client.get("/", headers={"accept-language": "es-ES,es;q=0.9"})
    assert '<html lang="es">' in es.text
    assert "Comparte secretos que" in es.text
    en = client.get("/")
    assert '<html lang="en">' in en.text
    assert "Share secrets that" in en.text


def test_error_pages_are_translated(client):
    r = client.get("/no-existeix", headers={"accept-language": "ca"})
    assert "senyal perdut" in r.text
    r = client.get("/no-existe", headers={"accept-language": "es"})
    assert "señal perdida" in r.text


def test_privacy_and_legal_translated(client):
    ca = client.get("/privacy", headers={"accept-language": "ca"})
    assert "Política de privacitat" in ca.text
    es = client.get("/legal", headers={"accept-language": "es"})
    assert "Aviso legal" in es.text
    assert "B27584010" in es.text


def test_api_stays_english(client):
    r404 = client.get("/api/secrets/" + "x" * 22, headers={"accept-language": "ca"})
    assert "not found" in r404.json()["detail"]


def test_html_varies_by_accept_language(client):
    r = client.get("/")
    assert "Accept-Language" in r.headers.get("vary", "")
    static = client.get("/static/css/app.css")
    assert "Accept-Language" not in static.headers.get("vary", "")
