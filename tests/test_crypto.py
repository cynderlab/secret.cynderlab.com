import pytest
from cryptography.exceptions import InvalidTag

from app import crypto


def test_slug_and_key_shapes():
    slug = crypto.new_slug()
    assert crypto.SLUG_RE.fullmatch(slug)
    assert len(crypto.new_key()) == 32
    assert crypto.new_slug() != crypto.new_slug()


def test_b64u_roundtrip_no_padding():
    data = bytes(range(32))
    s = crypto.b64u_encode(data)
    assert "=" not in s
    assert crypto.b64u_decode(s) == data


def test_encrypt_decrypt_roundtrip():
    slug, link_key = crypto.new_slug(), crypto.new_key()
    aes_key = crypto.derive_key(link_key, slug, None)
    nonce, ct = crypto.encrypt(b"deploy token: tk-123", aes_key, slug)
    assert crypto.decrypt(nonce, ct, aes_key, slug) == b"deploy token: tk-123"


def test_wrong_key_fails():
    slug = crypto.new_slug()
    aes_key = crypto.derive_key(crypto.new_key(), slug, None)
    nonce, ct = crypto.encrypt(b"x", aes_key, slug)
    bad = crypto.derive_key(crypto.new_key(), slug, None)
    with pytest.raises(InvalidTag):
        crypto.decrypt(nonce, ct, bad, slug)


def test_wrong_slug_aad_fails():
    slug, link_key = crypto.new_slug(), crypto.new_key()
    aes_key = crypto.derive_key(link_key, slug, None)
    nonce, ct = crypto.encrypt(b"x", aes_key, slug)
    with pytest.raises(InvalidTag):
        crypto.decrypt(nonce, ct, aes_key, crypto.new_slug())


def test_passphrase_changes_key_and_is_required():
    slug, link_key = crypto.new_slug(), crypto.new_key()
    with_pass = crypto.derive_key(link_key, slug, "correct horse")
    without = crypto.derive_key(link_key, slug, None)
    assert with_pass != without
    nonce, ct = crypto.encrypt(b"x", with_pass, slug)
    with pytest.raises(InvalidTag):
        crypto.decrypt(nonce, ct, crypto.derive_key(link_key, slug, "wrong"), slug)
    assert crypto.decrypt(nonce, ct, crypto.derive_key(link_key, slug, "correct horse"), slug) == b"x"


def test_known_vector_locks_scheme_v1():
    """Locks cross-language compatibility with static/js/crypto.js. Do not change."""
    link_key = bytes(range(32))
    slug = "AAAAAAAAAAAAAAAAAAAAAA"
    aes_key = crypto.derive_key(link_key, slug, "hunter2")
    assert crypto.b64u_encode(aes_key) == "aQ9zwdkp5wqhsrCL5-kxi7yy-sKCAfvDrl0DHgKd5KY"
