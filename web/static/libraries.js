// Library (TOML) editor: load / validate / save / delete libraries/*.toml.
(() => {
  const $ = (s) => document.querySelector(s);
  const nameEl = $("#lib-name"), contentEl = $("#lib-content"), statusEl = $("#lib-status");
  const bValidate = $("#lib-validate"), bSave = $("#lib-save"), bDelete = $("#lib-delete");
  let current = null;   // name of the file being edited (null = brand-new)

  function status(msg, kind) {
    statusEl.textContent = msg;
    statusEl.className = "lib-status " + (kind || "");
    statusEl.classList.toggle("hidden", !msg);
  }
  function setEditing(enabled) {
    [nameEl, contentEl, bValidate, bSave].forEach((el) => (el.disabled = !enabled));
    bDelete.disabled = !(enabled && current);   // can't delete an unsaved new file
  }

  // ---- load an existing file ----
  async function open(name) {
    const r = await fetch(`/api/libraries/${name}/raw`);
    if (!r.ok) return status("Could not load " + name, "err");
    const d = await r.json();
    current = name;
    nameEl.value = name; nameEl.disabled = true;     // name is fixed for existing files
    contentEl.value = d.content;
    setEditing(true);
    highlight(name);
    status("", "");
  }

  function highlight(name) {
    document.querySelectorAll(".lib-file").forEach((li) =>
      li.classList.toggle("active", li.dataset.name === name));
  }

  document.querySelectorAll(".lib-file").forEach((li) =>
    li.addEventListener("click", () => open(li.dataset.name)));

  // ---- new file ----
  $("#new-lib").addEventListener("click", async () => {
    current = null;
    highlight(null);
    nameEl.disabled = false; nameEl.value = "";
    const r = await fetch("/api/libraries/template");
    contentEl.value = (await r.json()).content;
    setEditing(true);
    nameEl.focus();
    status("New library — pick a name, edit, then Save.", "info");
  });

  // ---- validate (without saving) ----
  bValidate.addEventListener("click", async () => {
    const r = await fetch("/api/libraries/validate", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: contentEl.value }),
    });
    const d = await r.json();
    status(d.ok ? "✓ Valid — safe to save." : "✗ " + d.error, d.ok ? "ok" : "err");
  });

  // ---- save ----
  bSave.addEventListener("click", async () => {
    const name = (current || nameEl.value).trim().toLowerCase();
    if (!name) return status("Give the library a name first.", "err");
    const r = await fetch(`/api/libraries/${name}`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: contentEl.value }),
    });
    const d = await r.json();
    if (d.ok) { status("✓ Saved. Applies to the next scan.", "ok"); setTimeout(() => location.reload(), 700); }
    else status("✗ " + d.error, "err");
  });

  // ---- delete ----
  bDelete.addEventListener("click", async () => {
    if (!current || !confirm(`Delete libraries/${current}.toml?`)) return;
    const r = await fetch(`/api/libraries/${current}/delete`, { method: "POST" });
    const d = await r.json();
    if (d.ok) location.reload(); else status("✗ " + (d.error || "delete failed"), "err");
  });
})();
