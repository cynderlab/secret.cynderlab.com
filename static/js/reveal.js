(function () {
  "use strict";
  const $ = id => document.getElementById(id);
  const root = $("reveal-root");
  if (!root) return;
  const M = root.dataset;    // translated strings rendered server-side
  const slug = M.slug;
  const key = location.hash.slice(1);
  let needsPassphrase = false;

  // Anything broken — missing key, burned/expired secret, undecryptable link —
  // lands on the branded 404 page.
  const notFound = () => location.replace("/404");

  const states = ["state-loading", "state-ready", "state-secret"];
  function show(state) { for (const s of states) $(s).hidden = s !== state; }
  function fail(message, keepDisabled) {
    const el = $("reveal-error");
    el.textContent = message;
    el.hidden = false;
    $("reveal-btn").disabled = Boolean(keepDisabled);
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
    if (needsPassphrase && !passphrase) return fail(M.errNeedPass);

    // The passphrase never leaves the browser: only a derived verifier does.
    const body = {};
    if (needsPassphrase) {
      body.verifier = await CynderCrypto.deriveVerifier(passphrase, slug);
    }
    const res = await fetch(`/api/secrets/${slug}/consume`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (res.status === 403) {
      const info = await res.json().catch(() => ({}));
      return fail(M.errWrongPass.replace("{n}", info.attempts_left ?? "?"));
    }
    if (res.status === 429) {
      const info = await res.json().catch(() => ({}));
      const minutes = Math.max(1, Math.ceil((info.locked_seconds ?? 300) / 60));
      return fail(M.errLocked.replace("{m}", minutes), true);
    }
    if (!res.ok) return notFound();

    const payload = await res.json();
    try {
      const text = await CynderCrypto.decryptSecret(
        payload.ciphertext, payload.nonce, key, slug, passphrase);
      $("secret-text").textContent = text;
      show("state-secret");
    } catch (err) {
      notFound();    // wrong link key: the passphrase was already proven correct
    }
  }

  $("reveal-btn").addEventListener("click", reveal);
  $("copy-secret-btn").addEventListener("click", async () => {
    await navigator.clipboard.writeText($("secret-text").textContent);
    $("copy-secret-btn").textContent = M.copied;
    setTimeout(() => { $("copy-secret-btn").textContent = M.copyLabel; }, 1500);
  });
  init();
})();
