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

  // The decryption show: glyphs spin and lock left to right until the real
  // plaintext stands. Whitespace is kept in place so the layout never jumps,
  // and long secrets (>400 chars) skip the show — nobody wants to wait.
  const GLYPHS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789#$%&*+=?";
  function decodeInto(el, finalText, done) {
    const skip = matchMedia("(prefers-reduced-motion: reduce)").matches
                 || finalText.length > 400;
    if (skip) {
      el.textContent = finalText;
      if (done) done();
      return;
    }
    const chars = [...finalText];
    const frames = 26;                       // ~1s at 40ms/frame
    let frame = 0;
    const timer = setInterval(() => {
      frame++;
      const locked = Math.floor(chars.length * frame / frames);
      el.textContent = chars.map((c, i) =>
        (i < locked || /\s/.test(c)) ? c
          : GLYPHS[Math.floor(Math.random() * GLYPHS.length)]).join("");
      if (frame >= frames) {
        clearInterval(timer);
        el.textContent = finalText;
        if (done) done();
      }
    }, 40);
  }
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
      show("state-secret");
      const stamp = document.querySelector(".burned-stamp");
      decodeInto($("secret-text"), text, () => stamp.classList.add("slam"));
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
