(function () {
  "use strict";
  const $ = id => document.getElementById(id);
  const form = $("create-form");
  if (!form) return;
  const M = form.dataset;    // translated strings rendered server-side

  const MAX_BYTES = parseInt(M.maxBytes, 10) || 262144;
  const MAX_TTL_DAYS = parseInt(M.maxTtl, 10) || 30;
  const DEFAULT_TTL_DAYS = parseInt(M.defaultTtl, 10) || 3;
  const expiry = $("expiry-input");
  const today = new Date();
  const plusDays = d => {
    const x = new Date(today);
    x.setDate(x.getDate() + d);
    return x.toISOString().slice(0, 10);
  };
  expiry.min = plusDays(1);
  expiry.max = plusDays(MAX_TTL_DAYS);
  // Prefilled with the default self-destruct date so the lifetime is obvious.
  // These bounds are UX only — the backend re-validates everything.
  expiry.value = plusDays(DEFAULT_TTL_DAYS);
  // Open the calendar on click/focus so picking a date is one gesture.
  expiry.addEventListener("click", () => {
    try { expiry.showPicker(); } catch (e) { /* older browsers: native behaviour */ }
  });

  // The full link lives only here (and in the clipboard once copied); the page
  // shows a truncated version so a glance over the shoulder reveals nothing usable.
  let fullLink = null;
  let qrDrawn = false;

  function truncated(slug, key) {
    return `${location.host}/s/${slug.slice(0, 5)}…#${key.slice(0, 5)}…`;
  }

  // The forging show: characters spin like tumblers and lock into place left to
  // right until the link is fully formed. Pure cosmetics — the real link is
  // already sitting in `fullLink` before the first frame.
  const GLYPHS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789_-#/·";
  function forgeInto(el, finalText, done) {
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
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
        i < locked ? c : GLYPHS[Math.floor(Math.random() * GLYPHS.length)]).join("");
      if (frame >= frames) {
        clearInterval(timer);
        el.textContent = finalText;
        if (done) done();
      }
    }, 40);
  }

  function fail(message) {
    const el = $("create-error");
    el.textContent = message;
    el.hidden = false;
    $("create-btn").disabled = false;
  }

  // QR is generated locally (vendored qrcode.js): the link — and the key inside
  // it — never leaves the browser.
  function drawQr(link) {
    try {
      const qr = qrcode(0, "M");
      qr.addData(link);
      qr.make();
      $("result-qr").src = qr.createDataURL(4, 0);
      return true;
    } catch (e) {
      return false;                    // the link still works without a QR
    }
  }

  form.addEventListener("submit", async event => {
    event.preventDefault();
    $("create-error").hidden = true;
    $("create-btn").disabled = true;
    const secret = $("secret-input").value;
    if (new TextEncoder().encode(secret).length > MAX_BYTES) {
      return fail(M.errOversize);
    }
    const passphrase = $("passphrase-input").value || null;
    try {
      for (let attempt = 0; attempt < 3; attempt++) {
        const slug = CynderCrypto.newSlug();
        const enc = await CynderCrypto.encryptSecret(secret, slug, passphrase);
        const verifier = passphrase ? await CynderCrypto.deriveVerifier(passphrase, slug) : null;
        const res = await fetch("/api/secrets/encrypted", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            slug, ciphertext: enc.ciphertext, nonce: enc.nonce,
            has_passphrase: Boolean(passphrase),
            verifier,
            expires_at: expiry.value || null,
          }),
        });
        if (res.status === 409) continue;          // slug collision: rebuild with a new slug
        if (res.status === 429) return fail(M.errRate);
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          // detail is a string for our checks, a list for schema violations
          const detail = typeof body.detail === "string" ? body.detail : null;
          if (res.status === 422 && !detail) return fail(M.errInvalid);
          return fail(detail || M.errStore.replace("{status}", res.status));
        }
        const body = await res.json();
        fullLink = `${location.origin}/s/${slug}#${enc.key}`;
        $("result-meta").textContent =
          M.resultMeta.replace("{date}", body.expires_at.slice(0, 10));
        form.hidden = true;
        $("result-panel").hidden = false;
        const pill = $("result-link");
        forgeInto(pill, truncated(slug, enc.key), () => pill.classList.add("locked"));
        return;
      }
      fail(M.errAlloc);
    } catch (err) {
      fail(M.errCrypto);
    }
  });

  async function copyLink() {
    if (!fullLink) return;
    await navigator.clipboard.writeText(fullLink);
    $("copy-btn").textContent = M.copied;
    setTimeout(() => { $("copy-btn").textContent = M.copyLabel; }, 1500);
  }
  $("copy-btn").addEventListener("click", copyLink);
  $("result-link").addEventListener("click", copyLink);   // the pill copies too

  $("qr-toggle").addEventListener("click", () => {
    const box = $("qr-box");
    if (box.hidden && !qrDrawn) {
      if (!drawQr(fullLink)) {
        $("qr-toggle").hidden = true;  // can't draw it: remove the offer entirely
        return;
      }
      qrDrawn = true;
    }
    box.hidden = !box.hidden;
  });
})();
