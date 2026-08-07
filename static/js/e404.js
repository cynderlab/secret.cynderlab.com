/* 404 terminal: replays the forensics session with a typing effect.
 * Without JS (or with reduced motion) the full transcript is simply visible. */
(function () {
  "use strict";
  const term = document.getElementById("e404-terminal");
  if (!term) return;
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  const lines = Array.from(term.querySelectorAll("p"));
  const texts = lines.map(l => l.textContent);
  lines.forEach(l => { l.textContent = ""; l.classList.add("hold"); });

  let i = 0;
  function next() {
    if (i >= lines.length) return;
    const line = lines[i], full = texts[i];
    line.classList.remove("hold");
    if (line.classList.contains("out")) {
      // command output lands at once, like a real shell
      line.textContent = full;
      i++;
      setTimeout(next, 260);
      return;
    }
    line.classList.add("typing");
    let c = 0;
    const t = setInterval(() => {
      c++;
      line.textContent = full.slice(0, c);
      if (c >= full.length) {
        clearInterval(t);
        line.classList.remove("typing");
        i++;
        setTimeout(next, 180);
      }
    }, 22);
  }
  setTimeout(next, 350);
})();
