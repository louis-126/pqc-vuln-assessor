// Submit-page interactions: source tabs, library detection, scan + poll.
(() => {
  const $ = (s) => document.querySelector(s);
  const state = { kind: "github", resolvedPath: null, keySet: true, backendReady: false,
                  toolsReady: false, missingRequired: [], jobId: null, poll: null,
                  lastBackend: null, backendCheckId: 0,
                  modelSelections: {}, reviewerModelSelections: {} };

  // ---- source tabs ----
  document.querySelectorAll("#source-tabs .tab").forEach((t) => {
    t.addEventListener("click", () => {
      document.querySelectorAll("#source-tabs .tab").forEach((x) => x.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach((x) => x.classList.remove("active"));
      t.classList.add("active");
      state.kind = t.dataset.kind;
      $(`.tab-pane[data-pane="${state.kind}"]`).classList.add("active");
      updateReadiness();
    });
  });

  // ---- helpers ----
  function selectedGitRef() {
    const sel = $("#github-ref-select");
    if (!sel) return "";
    return sel.value === "__custom__" ? $("#custom-github-ref").value.trim() : sel.value.trim();
  }

  $("#github-ref-select").addEventListener("change", () => {
    const isCustom = $("#github-ref-select").value === "__custom__";
    $("#custom-github-ref").classList.toggle("hidden", !isCustom);
    if (isCustom) $("#custom-github-ref").focus();
  });

  let _lastTagsUrl = "";
  async function fetchGithubTags() {
    const url = $("#github-url").value.trim();
    if (!url || url === _lastTagsUrl) return;
    _lastTagsUrl = url;
    try {
      const r = await fetch("/api/github-tags", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }) });
      const d = await r.json();
      if (Array.isArray(d.tags) && d.tags.length > 0) {
        const refSel = $("#github-ref-select");
        const curr = selectedGitRef();
        refSel.innerHTML = `<option value="">— default branch (latest) —</option>` +
          d.tags.map((t) => `<option value="${t}">${t}</option>`).join("") +
          `<option value="__custom__">other (type tag/branch/commit)…</option>`;
        if ([...refSel.options].some((o) => o.value === curr)) {
          refSel.value = curr;
        }
      }
    } catch {}
  }
  $("#github-url").addEventListener("change", fetchGithubTags);
  $("#github-url").addEventListener("blur", fetchGithubTags);

  function currentSource() {
    if (state.kind === "github") return { kind: "github", source: $("#github-url").value.trim(), git_ref: selectedGitRef() };
    if (state.kind === "path") return { kind: "path", source: $("#local-path").value.trim() };
    return { kind: null, source: "" };
  }
  function selectedLibrary() {
    const v = $("#library").value;
    return v === "__custom__" ? $("#custom-library").value.trim() : v;
  }

  // ---- readiness: one checklist gates the scan button, always shows what's missing ----
  function setScanEnabled(on, hint) { $("#scan-btn").disabled = !on; if (hint) $("#scan-hint").textContent = hint; }
  function mark(req, ok) {
    const li = document.querySelector(`#ready-list li[data-req="${req}"]`);
    if (!li) return;
    li.classList.toggle("ok", ok);
    li.querySelector(".rl-mark").textContent = ok ? "✓" : "○";
  }
  function updateNextFieldHighlight() {
    document.querySelectorAll(".next-field-highlight").forEach((el) => el.classList.remove("next-field-highlight"));

    const src = currentSource();
    const hasSource = !!src.source;
    const hasLib = !!selectedLibrary();
    const ready = hasSource && hasLib && state.toolsReady && state.backendReady;

    if (!hasSource) {
      const activeInput = src.kind === "github" ? $("#github-url") : $("#local-path");
      if (activeInput) activeInput.classList.add("next-field-highlight");
    } else if (!hasLib) {
      const detectBtn = $("#detect-btn");
      const libSelect = $("#library");
      if (detectBtn && $("#detect-result").classList.contains("hidden")) {
        detectBtn.classList.add("next-field-highlight");
      } else if (libSelect) {
        libSelect.classList.add("next-field-highlight");
      }
    } else if (ready) {
      const scanBtn = $("#scan-btn");
      if (scanBtn) scanBtn.classList.add("next-field-highlight");
    }
  }

  function updateReadiness() {
    const hasSource = !!currentSource().source;
    const hasLib = !!selectedLibrary();
    const toolsOk = state.toolsReady;
    const backendOk = state.backendReady;
    mark("source", hasSource); mark("library", hasLib);
    mark("tools", toolsOk); mark("backend", backendOk);
    const ready = hasSource && hasLib && toolsOk && backendOk;
    const missing = [];
    if (!hasSource) missing.push("a source");
    if (!hasLib) missing.push("a library");
    if (!toolsOk) missing.push(state.missingRequired.length
      ? `${state.missingRequired.join(", ")} (install ripgrep)`
      : "a required tool (choose a library to check)");
    if (!backendOk) missing.push("a working AI provider");
    setScanEnabled(ready, ready ? "Everything's set — click Run scan."
                                : "Still need: " + missing.join(", ") + ".");
    updateNextFieldHighlight();
  }
  // Live-update readiness as the source fields are typed.
  ["#github-url", "#local-path"].forEach((s) => $(s).addEventListener("input", updateReadiness));

  // ---- plain-English descriptions that update as options change (CAPE-style) ----
  const DESC = {
    mode: {
      "reason": "",
      "agent": "Investigator drives read-only tools to confirm hypotheses.",
      "agent-review": "Investigator hunts, separate reviewer re-checks every finding.",
    },
    backend: {
      "ollama": "Runs locally — private, free, no API key required.",
      "anthropic": "",
    },
    passes: {
      "": "",
      "all": "Every surface, including provider/PKI layer.",
      "kem": "Key encapsulation surface (decaps, encap, keygen).",
      "sig": "Signature surface (sign, verify).",
      "sampling": "Sampling, RNG, encoding, modular reduction.",
      "pki": "Cert-path / OCSP / keystore code.",
    },
  };
  function setDesc(id, text) {
    const el = $("#" + id);
    if (!el) return;
    el.textContent = text || "";
    el.classList.toggle("hidden", !text);
  }
  function refreshDescs() {
    setDesc("mode-desc", DESC.mode[$("#mode").value]);
    setDesc("backend-desc", DESC.backend[$("#backend").value]);
    setDesc("passes-desc", DESC.passes[$("#discovery-passes").value]);
  }
  $("#mode").addEventListener("change", refreshDescs);
  $("#discovery-passes").addEventListener("change", refreshDescs);

  $("#library").addEventListener("change", () => {
    const custom = $("#library").value === "__custom__";
    $("#custom-library").classList.toggle("hidden", !custom);
    const lib = selectedLibrary();
    setDesc("library-desc", lib
      ? (custom ? "Discovery-only: no curated file, so symbol enumeration drives the hunt."
                : `Anchoring on the curated entry points in libraries/${lib}.toml.`)
      : "Pick the library, or click Detect library to identify it from the source.");
    loadDoctor();
    updateReadiness();
    updatePocHint();
  });
  $("#custom-library").addEventListener("input", () => { updateReadiness(); updatePocHint(); });
  function selectedModel() {
    const sel = $("#model-select");
    if (!sel) return "";
    return sel.value === "__custom__" ? $("#custom-model").value.trim() : sel.value.trim();
  }

  function selectedReviewerModel() {
    const sel = $("#reviewer-model-select");
    if (!sel) return "";
    return sel.value === "__custom__" ? $("#custom-reviewer-model").value.trim() : sel.value.trim();
  }

  function toggleReviewerModelVisibility() {
    const isAgentReview = $("#mode").value === "agent-review";
    const revContainer = $("#reviewer-model-container");
    if (revContainer) revContainer.classList.toggle("hidden", !isAgentReview);
  }
  $("#mode").addEventListener("change", () => { refreshDescs(); toggleReviewerModelVisibility(); });
  toggleReviewerModelVisibility();

  $("#model-select").addEventListener("change", () => {
    const isCustom = $("#model-select").value === "__custom__";
    $("#custom-model").classList.toggle("hidden", !isCustom);
    if (isCustom) $("#custom-model").focus();
  });

  $("#reviewer-model-select").addEventListener("change", () => {
    const isCustom = $("#reviewer-model-select").value === "__custom__";
    $("#custom-reviewer-model").classList.toggle("hidden", !isCustom);
    if (isCustom) $("#custom-reviewer-model").focus();
  });

  // ---- PoC generation options ----
  // The provider + model pickers are the shared component in pocmodels.js, the
  // same one the PoC packages page uses, so both screens behave identically.
  let pocModels = null;
  const selectedPocDrafter = () => (pocModels ? pocModels.value("drafter") : "");
  const selectedPocCritic = () => (pocModels ? pocModels.value("critic") : "");

  // The C emit path is the only one that produces buildable sources today; a
  // non-C target still gets a documented package, just no code. Say which you
  // are about to get rather than letting the result surprise you.
  const _C_LIBS = ["botan", "wolfssl", "liboqs", "pqclean", "openssl"];
  const _JAVA_LIBS = ["bouncycastle", "bc-java", "conscrypt"];
  function updatePocHint() {
    const hint = $("#poc-lang-hint");
    if (!hint) return;
    const lib = (selectedLibrary() || "").toLowerCase();
    const rounds = parseInt($("#poc-compile-rounds").value, 10) || 0;
    const isC = _C_LIBS.some((l) => lib.includes(l));
    const isJava = _JAVA_LIBS.some((l) => lib.includes(l));
    const parts = [];
    if (!lib) {
      parts.push("Pick a library to see what the PoC stage will emit.");
    } else if (isC) {
      parts.push("C target — emits <code>server.c</code>, <code>client.c</code>, " +
                 "<code>poc_net.h</code> and <code>build.sh</code>.");
    } else if (isJava) {
      parts.push("Java target — emits a standalone <code>PoC.java</code> plus " +
                 "<code>build.sh</code>/<code>build.bat</code>, compiled against the " +
                 "target's jars.");
    } else {
      parts.push("This target has no code generator, so the package will be a " +
                 "documented <code>README.md</code> only (<code>doc_only</code>).");
    }
    if (rounds > 0 && !isC) {
      parts.push("Compile-repair rounds only apply to C targets and will be ignored.");
    }
    const backend = $("#poc-backend") ? $("#poc-backend").value : "";
    if (backend && window.pocProviderNote) {
      parts.push(window.pocProviderNote(backend));
    }
    // A custom tag can still disagree with the provider — routing is by model
    // id, so say where it would actually run.
    if (backend && window.pocProviderMismatch) {
      const warn = window.pocProviderMismatch(
        backend, [selectedPocDrafter(), selectedPocCritic()].filter(Boolean));
      if (warn) parts.push(warn);
    }
    hint.innerHTML = parts.join(" ");
  }

  const pocCheck = $("#poc");
  if (pocCheck) {
    pocCheck.addEventListener("change", () => {
      $("#poc-options").classList.toggle("hidden", !pocCheck.checked);
      updatePocHint();
    });
  }
  $("#poc-compile-rounds").addEventListener("change", updatePocHint);

  function initPocPickers() {
    if (!$("#poc-backend") || typeof window.initPocModels !== "function") return;
    pocModels = window.initPocModels({
      provider: "#poc-backend",
      status: "#poc-backend-status",
      fields: {
        drafter: { sel: "#poc-drafter-select", custom: "#custom-poc-drafter" },
        critic: { sel: "#poc-critic-select", custom: "#custom-poc-critic" },
      },
      onChange: updatePocHint,
    });
  }

  function addModelOption(select, value, label, title = "") {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = label;
    if (title) option.title = title;
    select.appendChild(option);
    return option;
  }

  function restoreModelSelection(select, customInput, value, fallback = "") {
    const desired = value || fallback;
    if ([...select.options].some((option) => option.value === desired)) {
      select.value = desired;
      customInput.classList.add("hidden");
    } else if (desired) {
      select.value = "__custom__";
      customInput.value = desired;
      customInput.classList.remove("hidden");
    } else {
      select.value = "";
      customInput.classList.add("hidden");
    }
  }

  async function syncBackend() {
    const backend = $("#backend").value;
    if (state.lastBackend && state.lastBackend !== backend) {
      state.modelSelections[state.lastBackend] = selectedModel();
      state.reviewerModelSelections[state.lastBackend] = selectedReviewerModel();
    }
    const currentVal = state.lastBackend === backend
      ? selectedModel()
      : (state.modelSelections[backend] || "");
    const currentRevVal = state.lastBackend === backend
      ? selectedReviewerModel()
      : (state.reviewerModelSelections[backend] || "");
    const checkId = ++state.backendCheckId;

    $("#apikey-row").classList.toggle("hidden", backend !== "anthropic");
    setDesc("backend-desc", DESC.backend[backend]);
    // Live readiness probe: Ollama running? / Anthropic key set?
    const el = $("#backend-status");
    el.textContent = "checking backend…"; el.className = "key-status";
    try {
      const d = await (await fetch(`/api/backend-check?backend=${backend}`)).json();
      if (checkId !== state.backendCheckId || backend !== $("#backend").value) return;
      state.backendReady = !!d.ready;
      el.textContent = (d.ready ? "✓ " : "✗ ") + d.message;
      el.className = "key-status " + (d.ready ? "ok" : "missing");

      // Populate the provider's current model catalog. Anthropic returns newest
      // first, so the first model becomes the explicit UI selection.
      if (Array.isArray(d.models)) {
        const modelSelect = $("#model-select");
        const modelOptions = Array.isArray(d.model_options)
          ? d.model_options
          : d.models.map((id) => ({ id, display_name: id, created_at: "" }));
        modelSelect.replaceChildren();
        const placeholder = addModelOption(
          modelSelect,
          "",
          backend === "anthropic"
            ? (modelOptions.length
                ? "— choose an available Claude model —"
                : "— model list unavailable; set API key or choose custom —")
            : "— default (deepseek-r1:14b) —",
        );
        placeholder.selected = true;
        modelOptions.forEach((model) => {
          if (!model || typeof model.id !== "string") return;
          const name = typeof model.display_name === "string" ? model.display_name : model.id;
          const label = name === model.id ? model.id : `${name} — ${model.id}`;
          addModelOption(modelSelect, model.id, label, model.created_at || "");
        });
        addModelOption(modelSelect, "__custom__", "other (custom model tag)…");

        restoreModelSelection(
          modelSelect,
          $("#custom-model"),
          currentVal,
          backend === "anthropic" ? (d.default_model || "") : "",
        );

        const revSelect = $("#reviewer-model-select");
        if (revSelect) {
          revSelect.replaceChildren();
          addModelOption(revSelect, "", "— same as investigator —");
          modelOptions.forEach((model) => {
            if (!model || typeof model.id !== "string") return;
            const name = typeof model.display_name === "string" ? model.display_name : model.id;
            const label = name === model.id ? model.id : `${name} — ${model.id}`;
            addModelOption(revSelect, model.id, label, model.created_at || "");
          });
          addModelOption(revSelect, "__custom__", "other (custom model tag)…");
          restoreModelSelection(
            revSelect,
            $("#custom-reviewer-model"),
            currentRevVal,
          );
        }

        // NOTE: the PoC drafter/critic lists are deliberately NOT built here.
        // They are not bound to the scan backend — pipeline._poc_backend routes
        // any claude-* tag to Anthropic and everything else to local Ollama —
        // so they are populated by the shared picker in pocmodels.js.

      }
    } catch {
      if (checkId !== state.backendCheckId || backend !== $("#backend").value) return;
      state.backendReady = false;
      el.textContent = "✗ could not check the backend"; el.className = "key-status missing";
    }
    state.lastBackend = backend;
    loadDoctor();
    updateReadiness();
  }
  $("#backend").addEventListener("change", syncBackend);
  // Refresh the tools panel when a custom library name is typed (debounced).
  let _docTimer;
  $("#custom-library").addEventListener("input", () => {
    clearTimeout(_docTimer);
    _docTimer = setTimeout(loadDoctor, 400);
  });

  // ---- doctor (tool availability for the chosen library's language) ----
  // Also decides toolsReady: a REQUIRED tool missing (rg) hard-blocks the scan.
  async function loadDoctor() {
    const lib = selectedLibrary();
    if (!lib) {                       // can't check per-language tools yet
      $("#doctor").innerHTML = "";
      state.missingRequired = [];
      state.toolsReady = false;       // pending until a library is chosen
      updateReadiness();
      return;
    }
    try {
      const r = await fetch(`/api/doctor?library=${encodeURIComponent(lib)}`);
      const d = await r.json();
      state.missingRequired = d.tools.filter((t) => t.required && !t.installed).map((t) => t.tool);
      state.toolsReady = state.missingRequired.length === 0;
      const dots = d.tools.map((t) => {
        const cls = t.installed ? "ok" : (t.required ? "miss" : "opt");
        return `<span class="tool"><span class="dot ${cls}"></span>${t.tool}</span>`;
      }).join("");
      const warn = state.toolsReady ? ""
        : ` <span class="tool-warn">— missing ${state.missingRequired.join(", ")} (required)</span>`;
      $("#doctor").innerHTML = `<span class="muted">tools for <b>${d.lang}</b>:</span> ${dots}${warn}`;
    } catch { $("#doctor").innerHTML = ""; state.toolsReady = false; }
    updateReadiness();
  }

  // ---- drag a folder / file / path onto the Local-folder field ----
  const pathPane = $("#path-pane"), pathInput = $("#local-path"),
        dropHint = $("#drop-hint"), dzBox = $("#path-dropzone");

  function extractPathFromDrop(e) {
    const dt = e.dataTransfer;
    if (!dt) return null;

    // 1. Check native File.path (Electron / WebKit / Chrome desktop local file drops)
    if (dt.files && dt.files.length > 0) {
      for (let i = 0; i < dt.files.length; i++) {
        const f = dt.files[i];
        if (f && f.path) return f.path;
      }
    }
    if (dt.items && dt.items.length > 0) {
      for (let i = 0; i < dt.items.length; i++) {
        const item = dt.items[i];
        if (item.kind === "file") {
          const f = item.getAsFile ? item.getAsFile() : null;
          if (f && f.path) return f.path;
        }
      }
    }

    // 2. DataTransfer text formats across macOS Finder, Windows Explorer, Linux File Managers
    const types = ["text/uri-list", "text/plain", "URL", "text/x-moz-url", "text/html"];
    const rawTexts = [];
    for (const type of types) {
      try {
        const val = dt.getData(type);
        if (val) rawTexts.push(val);
      } catch (_) {}
    }

    for (let raw of rawTexts) {
      if (!raw) continue;
      const lines = raw.split(/[\r\n]+/);
      for (let line of lines) {
        line = line.trim();
        if (!line || line.startsWith("#")) continue;

        if (line.includes("href=") || line.includes("src=")) {
          const m = line.match(/(?:href|src)=["'](file:\/\/[^"']+)["']/i);
          if (m) line = m[1];
        }

        let parsed = line;
        if (parsed.toLowerCase().startsWith("file://")) {
          parsed = parsed.replace(/^file:\/\//i, "");
          parsed = parsed.replace(/^localhost\//i, "");
          try {
            parsed = decodeURIComponent(parsed);
          } catch (_) {}

          // Windows /C:/path -> C:/path or /C:\path -> C:\path
          if (/^\/[a-zA-Z]:[\\/]/i.test(parsed)) {
            parsed = parsed.substring(1);
          }
        } else {
          try {
            parsed = decodeURIComponent(parsed);
          } catch (_) {}
        }

        parsed = parsed.replace(/^["']|["']$/g, "").trim();

        // Valid OS absolute paths: Windows C:\... or \\server\..., Mac/Linux /... or ~/...
        if (
          /^[a-zA-Z]:[\\/]/i.test(parsed) ||
          /^\\\\/.test(parsed) ||
          parsed.startsWith("/") ||
          parsed.startsWith("~")
        ) {
          return parsed;
        }
      }
    }

    return null;
  }

  if (pathPane) {
    ["dragover", "dragenter"].forEach((ev) =>
      pathPane.addEventListener(ev, (e) => { e.preventDefault(); dzBox.classList.add("drag"); }));
    ["dragleave", "drop"].forEach((ev) =>
      pathPane.addEventListener(ev, () => dzBox.classList.remove("drag")));

    pathPane.addEventListener("drop", async (e) => {
      e.preventDefault();
      const extractedPath = extractPathFromDrop(e);

      if (extractedPath) {
        pathInput.value = extractedPath;
        dropHint.textContent = "Full path captured — confirm it's the source root, then Detect.";
        updateReadiness();
      } else {
        const dt = e.dataTransfer;
        const item = dt.items && dt.items[0] && dt.items[0].webkitGetAsEntry && dt.items[0].webkitGetAsEntry();
        const droppedName = (item && item.name) || (dt.files && dt.files[0] && dt.files[0].name) || "";

        if (droppedName) {
          dropHint.textContent = "Resolving path for '" + droppedName + "'…";
          try {
            const r = await fetch("/api/resolve-path", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ name: droppedName, path: droppedName })
            });
            const d = await r.json();
            if (d.path) {
              pathInput.value = d.path;
              dropHint.textContent = d.found
                ? "Full path captured — click Detect library."
                : "Path set — verify root directory, then Detect.";
              updateReadiness();
            } else {
              pathInput.value = droppedName;
              dropHint.textContent = "Path set — verify absolute path or use Browse.";
              updateReadiness();
            }
          } catch {
            pathInput.value = droppedName;
            dropHint.textContent = "Path set — type full path or click Browse.";
            updateReadiness();
          }
        }
      }
    });

    // Browse… → native folder dialog on the server (local tool), returns the
    // REAL absolute path. Falls back to a hint if no GUI is available.
    $("#browse-btn").addEventListener("click", async (e) => {
      e.stopPropagation();
      dropHint.textContent = "Opening folder picker… (check for a dialog window)";
      if (window.showSpinner) window.showSpinner("Opening folder dialog…");
      try {
        const r = await fetch("/api/browse", { method: "POST" });
        const d = await r.json();
        if (d.path) {
          pathInput.value = d.path;
          dropHint.textContent = "Folder selected — click Detect library.";
          updateReadiness();
        } else if (d.cancelled) {
          dropHint.textContent = "Cancelled — pick a folder or type the path.";
        } else {
          dropHint.textContent = d.error || "Could not open a folder picker — type the path.";
        }
      } catch { dropHint.textContent = "Could not open a folder picker — type the path instead."; }
      finally { if (window.hideSpinner) window.hideSpinner(); }
    });
  }

  // ---- detect library ----
  $("#detect-btn").addEventListener("click", async () => {
    const src = currentSource();
    if (!src.source) { $("#detect-result").className = "detect-box low"; $("#detect-result").textContent = "Provide a source first."; $("#detect-result").classList.remove("hidden"); return; }
    const box = $("#detect-result");
    box.classList.remove("hidden"); box.className = "detect-box"; box.textContent = "Detecting… (cloning if GitHub)";
    if (window.showSpinner) window.showSpinner(src.kind === "github" ? "Cloning & Analyzing Repository…" : "Detecting PQC Library…");
    try {
      const r = await fetch("/api/detect", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ source_kind: src.kind, source: src.source, git_ref: src.git_ref }) });
      const d = await r.json();
      if (d.error) throw new Error(d.error);
      state.resolvedPath = d.resolved_path;
      // GitHub clones get scanned from the resolved local checkout.
      if (src.kind === "github") { state.kind = "path"; $("#local-path").value = d.resolved_path; }
      box.className = "detect-box " + d.confidence;
      if (d.best) {
        $("#library").value = [...$("#library").options].some((o) => o.value === d.best) ? d.best : "__custom__";
        if ($("#library").value === "__custom__") { $("#custom-library").classList.remove("hidden"); $("#custom-library").value = d.best; }
        const top = d.ranking.slice(0, 3).map((x) => `${x.library} (${x.symbol_hits}/${x.symbols_total})`).join(", ");
        box.innerHTML = `<span class="conf-tag">${d.confidence} confidence</span> → <b>${d.best}</b><br><span class="muted">symbol matches: ${top}</span>`;
      } else {
        box.innerHTML = `<span class="conf-tag">no match</span> — no curated library detected. Pick one manually or use discovery-only.`;
      }
      const lib = selectedLibrary();
      setDesc("library-desc", lib
        ? `Detected — anchoring on libraries/${lib}.toml.`
        : "No curated library detected — pick one or use discovery-only.");
      loadDoctor();
      updateReadiness();
      updatePocHint();
    } catch (e) { box.className = "detect-box none"; box.textContent = "Detection failed: " + e.message; }
    finally { if (window.hideSpinner) window.hideSpinner(); }
  });

  // ---- run scan ----
  $("#scan-btn").addEventListener("click", async () => {
    const src = currentSource();
    const lib = selectedLibrary();
    if (!lib || !src.source) return setScanEnabled(false, "Need a source and a library.");
    if (!state.toolsReady) {
      return setScanEnabled(false, "ripgrep (rg) is required and not installed — run: apt install ripgrep");
    }
    const backend = $("#backend").value;
    if (backend === "anthropic" && !state.keySet) {
      return setScanEnabled(true, "Set ANTHROPIC_API_KEY in the server environment, then restart the app.");
    }
    const body = {
      source_kind: src.kind, source: src.source, library: lib,
      mode: $("#mode").value, backend: backend,
      model: selectedModel(),
      reviewer_model: selectedReviewerModel(),
      git_ref: src.git_ref,
      explain: $("#explain").checked,
      discovery_passes: $("#discovery-passes").value,
      poc: $("#poc").checked,
      poc_drafter_model: selectedPocDrafter(),
      poc_critic_model: selectedPocCritic(),
      poc_compile_rounds: parseInt($("#poc-compile-rounds").value, 10) || 0,
    };
    state.pocRequested = body.poc;
    try {
      const r = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const d = await r.json();
      if (d.error) throw new Error(d.error);
      state.jobId = d.id;
      $("#progress").classList.remove("hidden");
      $("#progress").scrollIntoView({ behavior: "smooth" });
      pollJob();
    } catch (e) { setScanEnabled(true, "Scan failed to start: " + e.message); }
  });

  $("#cancel-btn").addEventListener("click", async () => {
    if (state.jobId) await fetch(`/api/job/${state.jobId}/cancel`, { method: "POST" });
  });

  function pollJob() {
    clearInterval(state.poll);
    state.poll = setInterval(async () => {
      const r = await fetch(`/api/job/${state.jobId}`);
      const j = await r.json();
      if (j.error) { clearInterval(state.poll); return; }
      $("#prog-title").textContent = `${j.library} · ${j.mode}`;
      $("#prog-elapsed").textContent = j.elapsed + "s";
      $("#prog-badge").className = "badge " + j.state;
      $("#prog-badge").textContent = j.state;
      $("#prog-msg").textContent = j.message || "";
      const log = $("#prog-log");
      log.textContent = (j.log_tail || []).join("\n");
      log.scrollTop = log.scrollHeight;
      if (["done", "failed", "interrupted"].includes(j.state)) {
        clearInterval(state.poll);
        $("#cancel-btn").classList.add("hidden");
        if (j.run_id && j.state !== "failed") {
          const [lib, ts] = j.run_id.split("/");
          const url = `/scan/${lib}/${ts}`;
          const link = $("#view-result");
          link.href = url;
          link.classList.remove("hidden");
          if (j.poc && j.poc_count > 0) {
            // PoCs were produced: surface both destinations and let them
            // choose, instead of navigating away from the PoC link.
            const pocLink = $("#view-pocs");
            pocLink.href = `${url}/poc`;
            pocLink.textContent = `View ${j.poc_count} PoC package${j.poc_count === 1 ? "" : "s"} →`;
            pocLink.classList.remove("hidden");
            $("#prog-msg").textContent = j.message || "done";
          } else {
            // Send them straight to the result once the scan finishes.
            $("#prog-msg").textContent = "done — opening result…";
            setTimeout(() => { location.href = url; }, 900);
          }
        }
      }
    }, 1500);
  }

  refreshDescs();
  updatePocHint();     // describe what the PoC stage would emit right now
  updateReadiness();   // render the checklist immediately
  syncBackend();       // then probe the backend (async) and re-check
  initPocPickers();    // PoC provider + models, independent of the scan backend
})();
