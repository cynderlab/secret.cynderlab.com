(function () {
  "use strict";
  const $ = id => document.getElementById(id);
  const root = $("reveal-root");
  if (!root) return;
  const slug = root.dataset.slug;
  const key = location.hash.slice(1);
  let needsPassphrase = false;
  let cached = null;    // {ciphertext, nonce} kept so a wrong passphrase can be retried locally

  const states = ["state-loading", "state-ready", "state-secret", "state-gone", "state-nokey"];
  function show(state) { for (const s of states) $(s).hidden = s !== state; }
  function fail(message) {
    const el = $("reveal-error");
    el.textContent = message;
    el.hidden = false;
    $("reveal-btn").disabled = false;
  }

  async function init() {
    if (!key) return show("state-nokey");
    const res = await fetch(`/api/secrets/${slug}`);
    if (!res.ok) return show("state-gone");
    const meta = await res.json();
    needsPassphrase = meta.has_passphrase;
    $("passphrase-box").hidden = !needsPassphrase;
    show("state-ready");
  }

  async function reveal() {
    $("reveal-error").hidden = true;
    $("reveal-btn").disabled = true;
    const passphrase = needsPassphrase ? $("reveal-passphrase").value : null;
    if (needsPassphrase && !passphrase) return fail("Enter the passphrase first.");
    if (!cached) {
      const res = await fetch(`/api/secrets/${slug}/consume`, { method: "POST" });
      if (!res.ok) return show("state-gone");
      cached = await res.json();
    }
    try {
      const text = await CynderCrypto.decryptSecret(cached.ciphertext, cached.nonce, key, slug, passphrase);
      $("secret-text").textContent = text;
      show("state-secret");
    } catch (err) {
      if (needsPassphrase) {
        fail("Wrong passphrase. The secret is already burned on the server, but you can retry here — do not close this tab.");
      } else {
        fail("Decryption failed: the key in this link does not match. The secret is burned.");
      }
    }
  }

  $("reveal-btn").addEventListener("click", reveal);
  $("copy-secret-btn").addEventListener("click", async () => {
    await navigator.clipboard.writeText($("secret-text").textContent);
    $("copy-secret-btn").textContent = "Copied ✔";
    setTimeout(() => { $("copy-secret-btn").textContent = "Copy secret"; }, 1500);
  });
  init();
})();
