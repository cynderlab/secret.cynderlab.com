(function () {
  "use strict";
  const $ = id => document.getElementById(id);
  const tabs = {
    human: { btn: $("tab-human"), panel: $("how-it-works") },
    machine: { btn: $("tab-agent"), panel: $("agents") },
  };
  if (!tabs.human.btn) return;

  function activate(which) {
    for (const [name, t] of Object.entries(tabs)) {
      const on = name === which;
      t.btn.classList.toggle("is-active", on);
      t.btn.setAttribute("aria-selected", String(on));
      t.panel.hidden = !on;
    }
  }

  tabs.human.btn.addEventListener("click", () => activate("human"));
  tabs.machine.btn.addEventListener("click", () => activate("machine"));

  // Header links (/#how-it-works, /#agents) select the matching mode.
  function fromHash() {
    if (location.hash === "#agents") activate("machine");
    else if (location.hash === "#how-it-works") activate("human");
  }
  window.addEventListener("hashchange", fromHash);
  fromHash();
})();
