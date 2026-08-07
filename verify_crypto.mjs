import { readFileSync } from "fs";

// Browser shims for crypto.js
globalThis.window = globalThis;
globalThis.btoa = s => Buffer.from(s, "binary").toString("base64");
globalThis.atob = s => Buffer.from(s, "base64").toString("binary");

eval(readFileSync(new URL("./static/js/crypto.js", import.meta.url), "utf8"));
const C = globalThis.CynderCrypto;

// 1) KDF test vector (deriveBits variant, same params as deriveAesKey)
const te = new TextEncoder();
const lk = Uint8Array.from({ length: 32 }, (_, i) => i);
const pk = await crypto.subtle.importKey("raw", te.encode("hunter2"), "PBKDF2", false, ["deriveBits"]);
const salt = new Uint8Array(await crypto.subtle.deriveBits(
  { name: "PBKDF2", hash: "SHA-256", salt: te.encode("AAAAAAAAAAAAAAAAAAAAAA"), iterations: 310000 }, pk, 256));
const ikm = await crypto.subtle.importKey("raw", lk, "HKDF", false, ["deriveBits"]);
const bits = new Uint8Array(await crypto.subtle.deriveBits(
  { name: "HKDF", hash: "SHA-256", salt, info: te.encode("cynderlab.secret.v1") }, ikm, 256));
const vector = C.b64uEncode(bits);
console.log("vector:", vector);
if (vector !== "aQ9zwdkp5wqhsrCL5-kxi7yy-sKCAfvDrl0DHgKd5KY") throw new Error("KDF vector MISMATCH");

// 2) JS-encrypt -> print for Python decrypt
const slug = C.newSlug();
const enc = await C.encryptSecret("cross-language payload ✔", slug, "correct horse");
console.log(JSON.stringify({ slug, ...enc }));

// 3) JS roundtrip including wrong-passphrase failure
const ok = await C.decryptSecret(enc.ciphertext, enc.nonce, enc.key, slug, "correct horse");
if (ok !== "cross-language payload ✔") throw new Error("JS roundtrip failed");
let failed = false;
try { await C.decryptSecret(enc.ciphertext, enc.nonce, enc.key, slug, "wrong"); }
catch { failed = true; }
if (!failed) throw new Error("wrong passphrase should fail");
console.log("JS roundtrip + wrong-passphrase rejection: OK");
