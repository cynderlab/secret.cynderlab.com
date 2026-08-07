/* Mirror of app/crypto.py — scheme cynderlab.secret.v1.
 * Test vectors (tests/test_crypto.py):
 *   linkKey=bytes 0..31, slug="AAAAAAAAAAAAAAAAAAAAAA", passphrase="hunter2"
 *   => b64u(aesKeyBits) === "aQ9zwdkp5wqhsrCL5-kxi7yy-sKCAfvDrl0DHgKd5KY"
 *   deriveVerifier("hunter2", "AAAAAAAAAAAAAAAAAAAAAA")
 *   => "6cG5RzzGKJuDk7J761se5TuxDPtCpXizEfxGyjn4gpY" */
(function () {
  "use strict";
  const te = new TextEncoder(), td = new TextDecoder();
  const HKDF_INFO = te.encode("cynderlab.secret.v1");
  const PBKDF2_ITERATIONS = 310000;

  function b64uEncode(bytes) {
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  }
  function b64uDecode(str) {
    const s = atob(str.replaceAll("-", "+").replaceAll("_", "/"));
    return Uint8Array.from(s, c => c.charCodeAt(0));
  }
  function randomBytes(n) { return crypto.getRandomValues(new Uint8Array(n)); }
  function newSlug() { return b64uEncode(randomBytes(16)); }

  async function deriveAesKey(linkKey, slug, passphrase, usages) {
    let salt = new Uint8Array(0);
    if (passphrase) {
      const pk = await crypto.subtle.importKey("raw", te.encode(passphrase), "PBKDF2", false, ["deriveBits"]);
      salt = new Uint8Array(await crypto.subtle.deriveBits(
        { name: "PBKDF2", hash: "SHA-256", salt: te.encode(slug), iterations: PBKDF2_ITERATIONS },
        pk, 256));
    }
    const ikm = await crypto.subtle.importKey("raw", linkKey, "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info: HKDF_INFO },
      ikm, { name: "AES-GCM", length: 256 }, false, usages);
  }

  // Proof-of-passphrase for the server gate. Domain-separated from the AES key
  // by the ".verify" salt suffix; the server stores only its sha256.
  async function deriveVerifier(passphrase, slug) {
    const pk = await crypto.subtle.importKey("raw", te.encode(passphrase), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: te.encode(slug + ".verify"), iterations: PBKDF2_ITERATIONS },
      pk, 256);
    return b64uEncode(new Uint8Array(bits));
  }

  async function encryptSecret(plaintext, slug, passphrase) {
    const linkKey = randomBytes(32);
    const aesKey = await deriveAesKey(linkKey, slug, passphrase, ["encrypt"]);
    const nonce = randomBytes(12);
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: te.encode(slug) },
      aesKey, te.encode(plaintext));
    return { key: b64uEncode(linkKey), nonce: b64uEncode(nonce),
             ciphertext: b64uEncode(new Uint8Array(ct)) };
  }

  async function decryptSecret(ciphertextB64, nonceB64, keyB64, slug, passphrase) {
    const aesKey = await deriveAesKey(b64uDecode(keyB64), slug, passphrase, ["decrypt"]);
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64uDecode(nonceB64), additionalData: te.encode(slug) },
      aesKey, b64uDecode(ciphertextB64));
    return td.decode(pt);
  }

  window.CynderCrypto = { b64uEncode, b64uDecode, randomBytes, newSlug,
                          deriveAesKey, deriveVerifier, encryptSecret, decryptSecret };
})();
