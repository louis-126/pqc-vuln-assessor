/* Shared "AI Provider + model" picker for PoC generation.
 *
 * Mirrors the New Scan card: a provider select, a live readiness line, and
 * model dropdowns filled from that provider's real catalog. Used by BOTH the
 * scan form's PoC options block and the standalone generate panel on the PoC
 * packages page, so the two behave identically.
 *
 * Why a provider select rather than one merged list: pipeline._poc_backend
 * routes per MODEL ID (claude-* -> Anthropic, anything else -> local Ollama).
 * Picking the provider first means the drafter and critic always come from the
 * same place, which removes the pairing that silently kills the PoC stage — a
 * Claude drafter with the default local critic and no Ollama running.
 *
 * window.initPocModels(cfg) -> { sync, value(role), provider() }
 *   cfg.provider   selector for the <select> of backends
 *   cfg.status     selector for the readiness line
 *   cfg.fields     { role: {sel, custom} } — the model selects + custom inputs
 *   cfg.preferModel  model id to preselect when the provider offers it
 *   cfg.onChange   called after any repopulation / selection change
 */
(function () {
  const $ = (s) => document.querySelector(s);

  const PROVIDER_NOTE = {
    anthropic: "Cloud API — bills your ANTHROPIC_API_KEY.",
    ollama: "Runs locally — free, but needs `ollama serve` running.",
  };

  function providerOf(modelId) {
    return (modelId || "").startsWith("claude-") ? "anthropic" : "ollama";
  }

  window.pocProviderOf = providerOf;

  window.initPocModels = function (cfg) {
    const provider = $(cfg.provider);
    const status = cfg.status ? $(cfg.status) : null;
    const roles = Object.keys(cfg.fields);
    if (!provider) return null;

    // Remember a selection per provider, so flipping back and forth does not
    // silently reset what was chosen (same behaviour as the scan form).
    const remembered = {};
    let checkId = 0;
    // By the time a 'change' event fires, provider.value is ALREADY the new
    // value — so the outgoing selections have to be filed against the provider
    // we are leaving, tracked here. Getting this wrong carried a Claude model
    // straight into the Ollama list.
    let lastProvider = provider.value;

    function value(role) {
      const f = cfg.fields[role];
      const sel = $(f.sel);
      if (!sel) return "";
      return sel.value === "__custom__"
        ? ($(f.custom) ? $(f.custom).value.trim() : "")
        : sel.value.trim();
    }

    function remember(p) {
      remembered[p] = remembered[p] || {};
      roles.forEach((r) => { remembered[p][r] = value(r); });
    }

    function fill(sel, customInput, models, options, desired) {
      sel.replaceChildren();
      const ph = document.createElement("option");
      ph.value = "";
      ph.textContent = models.length
        ? "— provider default —"
        : "— no models available —";
      sel.appendChild(ph);

      const opts = (options && options.length)
        ? options
        : models.map((id) => ({ id, display_name: id }));
      opts.forEach((m) => {
        if (!m || typeof m.id !== "string") return;
        const o = document.createElement("option");
        o.value = m.id;
        const name = typeof m.display_name === "string" ? m.display_name : m.id;
        o.textContent = name === m.id ? m.id : `${name} — ${m.id}`;
        sel.appendChild(o);
      });

      const custom = document.createElement("option");
      custom.value = "__custom__";
      custom.textContent = "other (custom model tag)…";
      sel.appendChild(custom);

      if (desired && [...sel.options].some((o) => o.value === desired)) {
        sel.value = desired;
        if (customInput) customInput.classList.add("hidden");
      } else if (desired) {
        sel.value = "__custom__";
        if (customInput) {
          customInput.value = desired;
          customInput.classList.remove("hidden");
        }
      } else {
        sel.value = "";
        if (customInput) customInput.classList.add("hidden");
      }
    }

    async function sync() {
      const backend = provider.value;
      const mine = ++checkId;
      if (status) {
        status.textContent = "checking AI provider…";
        status.className = "key-status";
      }
      let d = {};
      try {
        d = await (await fetch(`/api/backend-check?backend=${backend}`)).json();
      } catch (e) {
        d = { ready: false, models: [], message: "could not check this provider" };
      }
      if (mine !== checkId || backend !== provider.value) return;   // superseded

      if (status) {
        status.textContent = (d.ready ? "✓ " : "✗ ") + (d.message || "");
        status.className = "key-status " + (d.ready ? "ok" : "missing");
      }

      const prev = remembered[backend] || {};
      roles.forEach((role) => {
        const f = cfg.fields[role];
        const sel = $(f.sel);
        if (!sel) return;
        // First paint prefers the caller's hint (e.g. the model this run used).
        const desired = prev[role] !== undefined
          ? prev[role]
          : (cfg.preferModel && providerOf(cfg.preferModel) === backend
              ? cfg.preferModel : "");
        fill(sel, $(f.custom), d.models || [], d.model_options, desired);
      });
      if (cfg.onChange) cfg.onChange();
    }

    provider.addEventListener("change", () => {
      remember(lastProvider);         // file them against the provider we left
      lastProvider = provider.value;
      sync();
    });

    roles.forEach((role) => {
      const f = cfg.fields[role];
      const sel = $(f.sel);
      const customInput = $(f.custom);
      if (!sel) return;
      sel.addEventListener("change", () => {
        const isCustom = sel.value === "__custom__";
        if (customInput) {
          customInput.classList.toggle("hidden", !isCustom);
          if (isCustom) customInput.focus();
        }
        // Choosing a drafter pulls an unset critic along, so the two stay on
        // the same provider without the user having to think about it.
        if (role === "drafter" && cfg.fields.critic && sel.value) {
          const critic = $(cfg.fields.critic.sel);
          if (critic && !critic.value &&
              [...critic.options].some((o) => o.value === sel.value)) {
            critic.value = sel.value;
            const cc = $(cfg.fields.critic.custom);
            if (cc) cc.classList.add("hidden");
          }
        }
        if (cfg.onChange) cfg.onChange();
      });
      if (customInput) {
        customInput.addEventListener("input", () => {
          if (cfg.onChange) cfg.onChange();
        });
      }
    });

    // Open on the provider that matches the caller's preferred model.
    if (cfg.preferModel) {
      const want = providerOf(cfg.preferModel);
      if ([...provider.options].some((o) => o.value === want)) provider.value = want;
    }
    lastProvider = provider.value;
    sync();

    return { sync, value, provider: () => provider.value };
  };

  /* A custom tag that does not match the selected provider is a real trap:
   * routing is by model id, so "gpt-4" under the Anthropic provider still goes
   * to Ollama. Returns a warning string, or "". */
  window.pocProviderMismatch = function (backend, models) {
    const bad = [...new Set(models.filter((m) => m && providerOf(m) !== backend))];
    if (!bad.length) return "";
    return `⚠ <code>${bad.join("</code>, <code>")}</code> ` +
           `${bad.length > 1 ? "do" : "does"} not match the selected provider — ` +
           "PoC models are routed by id, so " +
           (backend === "anthropic"
             ? "this will run on local Ollama, not Anthropic."
             : "this will be sent to Anthropic and billed.");
  };

  window.pocProviderNote = (backend) => PROVIDER_NOTE[backend] || "";
})();
