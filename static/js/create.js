(function () {
  "use strict";
  const $ = id => document.getElementById(id);
  const form = $("create-form");
  if (!form) return;
  const M = form.dataset;    // translated strings rendered server-side

  const MAX_BYTES = 262144;
  const expiry = $("expiry-input");
  const today = new Date();
  const plusDays = d => {
    const x = new Date(today);
    x.setDate(x.getDate() + d);
    return x.toISOString().slice(0, 10);
  };
  expiry.min = plusDays(1);
  expiry.max = plusDays(30);
  // Open the calendar on click/focus so picking a date is one gesture.
  expiry.addEventListener("click", () => {
    try { expiry.showPicker(); } catch (e) { /* older browsers: native behaviour */ }
  });

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
    } catch (e) {
      document.querySelector(".qr-row").hidden = true;   // link still works without it
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
          return fail(body.detail || M.errStore.replace("{status}", res.status));
        }
        const body = await res.json();
        const link = `${location.origin}/s/${slug}#${enc.key}`;
        $("result-link").textContent = link;
        $("result-expiry").textContent = M.expiresTpl.replace("{date}", body.expires_at);
        drawQr(link);
        form.hidden = true;
        $("result-panel").hidden = false;
        return;
      }
      fail(M.errAlloc);
    } catch (err) {
      fail(M.errCrypto);
    }
  });

  $("copy-btn").addEventListener("click", async () => {
    await navigator.clipboard.writeText($("result-link").textContent);
    $("copy-btn").textContent = M.copied;
    setTimeout(() => { $("copy-btn").textContent = M.copyLabel; }, 1500);
  });
})();
