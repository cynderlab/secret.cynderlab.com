"""Live E2E of the passphrase gate against a running instance. Usage:
    uv run python gate_e2e.py [base_url]
"""

import json
import sys
import urllib.request

from app import crypto

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8001"


def call(method, path, payload=None):
    req = urllib.request.Request(
        f"{BASE}{path}", method=method,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def make_gated(passphrase):
    slug, link_key = crypto.new_slug(), crypto.new_key()
    aes = crypto.derive_key(link_key, slug, passphrase)
    nonce, ct = crypto.encrypt(b"gate e2e payload", aes, slug)
    status, _ = call("POST", "/api/secrets/encrypted", {
        "slug": slug, "ciphertext": crypto.b64u_encode(ct),
        "nonce": crypto.b64u_encode(nonce), "has_passphrase": True,
        "verifier": crypto.b64u_encode(crypto.derive_verifier(passphrase, slug))})
    assert status == 201, status
    return slug, link_key


def verifier_for(slug, passphrase):
    return {"verifier": crypto.b64u_encode(crypto.derive_verifier(passphrase, slug))}


# 1) wrong attempts count down, nothing burns
slug, link_key = make_gated("right horse")
for expected in (4, 3, 2, 1):
    status, body = call("POST", f"/api/secrets/{slug}/consume", verifier_for(slug, "wrong"))
    assert (status, body.get("attempts_left")) == (403, expected), (status, body)
print("4 wrong attempts -> 403 with countdown OK")

status, body = call("POST", f"/api/secrets/{slug}/consume", verifier_for(slug, "wrong"))
assert status == 429 and body["locked_seconds"] > 0, (status, body)
print(f"5th wrong attempt -> 429, locked {body['locked_seconds']}s OK")

status, _ = call("POST", f"/api/secrets/{slug}/consume", verifier_for(slug, "right horse"))
assert status == 429, status
print("correct passphrase while locked -> 429 OK")

status, _ = call("GET", f"/api/secrets/{slug}")
assert status == 200, status
print("secret still alive after all failures OK")

# 2) fresh secret: correct passphrase consumes, decrypts and burns
slug2, link_key2 = make_gated("open sesame")
status, body = call("POST", f"/api/secrets/{slug2}/consume", verifier_for(slug2, "open sesame"))
assert status == 200, (status, body)
aes = crypto.derive_key(link_key2, slug2, "open sesame")
plaintext = crypto.decrypt(crypto.b64u_decode(body["nonce"]),
                           crypto.b64u_decode(body["ciphertext"]), aes, slug2)
assert plaintext == b"gate e2e payload"
status, _ = call("POST", f"/api/secrets/{slug2}/consume", verifier_for(slug2, "open sesame"))
assert status == 404, status
print("correct passphrase -> consume + decrypt + burn OK")

print("ALL GATE E2E CHECKS PASSED")
