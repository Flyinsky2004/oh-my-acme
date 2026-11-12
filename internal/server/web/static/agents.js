(() => {
  // A page may load this asset more than once (for example after an in-place
  // navigation). Bind once so a single click never copies twice.
  if (window.__agentsUI) {
    return;
  }
  window.__agentsUI = true;

  // Per-button copy feedback state. The original label and aria-label are
  // captured once, so rapid repeat clicks can never treat "已复制" as the
  // value to restore. The generation counter makes stale async results and
  // stale timers harmless.
  const copyState = new WeakMap();

  function copyStateFor(button) {
    let state = copyState.get(button);
    if (!state) {
      const label = button.querySelector("span") || button;
      state = {
        label,
        originalLabel: label.textContent,
        originalAria: button.getAttribute("aria-label") || label.textContent,
        timer: null,
        generation: 0,
      };
      copyState.set(button, state);
    }
    return state;
  }

  function copyText(text, done) {
    if (typeof navigator !== "undefined" && navigator.clipboard &&
        typeof navigator.clipboard.writeText === "function" && window.isSecureContext) {
      try {
        navigator.clipboard.writeText(text).then(
          () => done(true),
          () => done(false),
        );
      } catch (_) {
        done(false);
      }
      return;
    }
    if (!document.body) {
      done(false);
      return;
    }
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.focus();
    area.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (_) {
      ok = false;
    }
    document.body.removeChild(area);
    done(ok);
  }

  document.addEventListener("click", (event) => {
    const target = event.target;
    if (!target || typeof target.closest !== "function") {
      return;
    }
    const button = target.closest("[data-copy-target]");
    if (!button) {
      return;
    }
    const code = document.getElementById(button.getAttribute("data-copy-target"));
    if (!code) {
      return;
    }
    const state = copyStateFor(button);
    const generation = ++state.generation;
    if (state.timer !== null) {
      clearTimeout(state.timer);
      state.timer = null;
    }
    // Copy exactly what is currently displayed, so the sudo toggle and the
    // clipboard can never disagree.
    copyText(code.textContent, (ok) => {
      if (generation !== state.generation) {
        return;
      }
      const feedback = ok ? "已复制" : "复制失败";
      state.label.textContent = feedback;
      button.setAttribute("aria-label", feedback);
      state.timer = setTimeout(() => {
        if (generation !== state.generation) {
          return;
        }
        state.label.textContent = state.originalLabel;
        button.setAttribute("aria-label", state.originalAria);
        state.timer = null;
      }, 1600);
    });
  });

  document.addEventListener("change", (event) => {
    const target = event.target;
    if (!target || typeof target.closest !== "function") {
      return;
    }
    const toggle = target.closest("[data-install-sudo]");
    if (!toggle) {
      return;
    }
    const section = toggle.closest("[data-install-command]");
    if (!section) {
      return;
    }
    const code = section.querySelector("code");
    if (!code) {
      return;
    }
    // Both variants are produced by the Server; only the outermost elevation
    // prefix differs. Never rebuild or rewrite the command in the browser.
    const command = toggle.checked
      ? section.getAttribute("data-command-sudo")
      : section.getAttribute("data-command-plain");
    if (typeof command === "string") {
      code.textContent = command;
    }
  });
})();
