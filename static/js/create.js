(function () {
  "use strict";
  const $ = id => document.getElementById(id);
  const form = $("create-form");
  if (!form) return;

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

  function fail(message) {
    const el = $("create-error");
    el.textContent = message;
    el.hidden = false;
    $("create-btn").disabled = false;
  }

  form.addEventListener("submit", async event => {
    event.preventDefault();
    $("create-error").hidden = true;
    $("create-btn").disabled = true;
    const secret = $("secret-input").value;
    if (new TextEncoder().encode(secret).length > MAX_BYTES) {
      return fail("Secret exceeds 256 KB. Trim it or split it.");
    }
    const passphrase = $("passphrase-input").value || null;
    try {
      for (let attempt = 0; attempt < 3; attempt++) {
        const slug = CynderCrypto.newSlug();
        const enc = await CynderCrypto.encryptSecret(secret, slug, passphrase);
        const res = await fetch("/api/secrets/encrypted", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            slug, ciphertext: enc.ciphertext, nonce: enc.nonce,
            has_passphrase: Boolean(passphrase),
            expires_at: expiry.value || null,
          }),
        });
        if (res.status === 409) continue;          // slug collision: rebuild with a new slug
        if (res.status === 429) return fail("Rate limit reached. Try again in a while.");
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          return fail(body.detail || `Could not store the secret (HTTP ${res.status}).`);
        }
        const body = await res.json();
        $("result-link").textContent = `${location.origin}/s/${slug}#${enc.key}`;
        $("result-expiry").textContent = `# expires ${body.expires_at} if never read`;
        form.hidden = true;
        $("result-panel").hidden = false;
        return;
      }
      fail("Could not allocate a link. Try again.");
    } catch (err) {
      fail("Encryption failed in this browser. It needs WebCrypto (any modern browser).");
    }
  });

  $("copy-btn").addEventListener("click", async () => {
    await navigator.clipboard.writeText($("result-link").textContent);
    $("copy-btn").textContent = "Copied ✔";
    setTimeout(() => { $("copy-btn").textContent = "Copy link"; }, 1500);
  });
})();
