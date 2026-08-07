(function () {
  "use strict";
  const $ = id => document.getElementById(id);
  const root = $("reveal-root");
  if (!root) return;
  const slug = root.dataset.slug;
  const key = location.hash.slice(1);
  let needsPassphrase = false;
  let cached = null;    // {ciphertext, nonce} kept so a wrong passphrase can be retried locally

  // Anything broken — missing key, burned/expired secret, undecryptable link —
  // lands on the branded 404 page.
  const notFound = () => location.replace("/404");

  const states = ["state-loading", "state-ready", "state-secret"];
  function show(state) { for (const s of states) $(s).hidden = s !== state; }
  function fail(message) {
    const el = $("reveal-error");
    el.textContent = message;
    el.hidden = false;
    $("reveal-btn").disabled = false;
  }

  async function init() {
    if (!key) return notFound();
    const res = await fetch(`/api/secrets/${slug}`);
    if (!res.ok) return notFound();
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
      if (!res.ok) return notFound();
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
        notFound();
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
