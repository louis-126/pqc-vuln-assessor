# PQC Assessor — Web Frontend

A local web UI over the `main.py` CLI. It doesn't reimplement the scanner — it
shells out to `python3 main.py …` for every scan, so each run produces the exact
same artifacts the CLI does (`report.html` / `report.md` / `report.json`,
`run.log`, `run.json` manifest, and the `runs/<lib>/latest` symlink).

## What it adds

1. **Submit page** — start a scan from a **GitHub URL** (shallow-cloned locally)
   or a **local folder** (scanned in place, zero-copy). The local-folder field is
   a **filepath drop target**: drag a path from a terminal/editor to fill it
   verbatim, or drop a folder to seed its name (browsers can't read a folder's
   absolute path, so you confirm the parent). Nothing is uploaded/copied.
2. **Library auto-detection** — greps each curated library's own entry-point
   symbols (from `libraries/*.toml`) against the target and picks the best match
   with a confidence level. Reuses the same data the scanner anchors on.
3. **Options that mirror the CLI** — mode (`reason` / `agent` / `agent-review`),
   backend (`ollama` / `anthropic`), investigator and reviewer model selectors,
   `--explain`, and **discovery passes** (`PQC_DISCOVERY_PASSES`:
   `kem`/`sig`/`sampling`/`pki`/`all`). Ollama choices come from its local tags;
   Anthropic choices come from the authenticated Models API, with the newest
   available model selected automatically. The page always shows the exact
   investigator and reviewer models that will be used.
4. **Anthropic key from the environment** — when the `anthropic` backend is
   selected the page shows whether `ANTHROPIC_API_KEY` is set in the server
   environment (boolean only, never the value). The key is **never entered in or
   sent through the browser**; the scan subprocess reads it from the inherited
   environment, exactly like the CLI.
5. **Preflight (`--doctor`)** — shows which analysis tools are installed for the
   detected library's language (no Go/Java noise on a C/C++ target).
6. **Live progress → result** — polls the running job and tails `run.log`; a
   **Cancel** button sends SIGINT so the CLI still writes a partial report. When
   the scan finishes it **redirects straight to the result page**.
7. **Scan history** — every run under `runs/`, newest first, with **per-scan
   delete** and a **"Clear all runs & clones"** button that also prunes the
   cached repo clones in `web/workspaces/` (freeing disk).
8. **Result viewer** — severity summary, the **Scope & Coverage** table
   (per-entry-point disposition + per-pass risky-line counts), findings with
   CWE/CVSS/evidence, a clean-run true-negative banner, a **Delete scan** button,
   and links to the raw `report.html` / `run.log` / manifest.
9. **Library editor** (`/libraries`) — view/edit/create/delete the
   `libraries/*.toml` definitions in the browser. Every save is validated the
   same way the scanner loads them (bad `lang`, non-list entry points → rejected)
   and `config` is hot-reloaded, so edits apply to the next scan without a
   restart.

Built to be **hard to misuse**: the library dropdown starts blank until you
detect or choose one; every option has an ⓘ tip and a plain-English description
that updates as you change it; and a "how a scan works in 3 steps" panel greets
newcomers. Defaults (local Ollama, `agent-review`) are safe — you only need to
set a source and a library.

## Run it

```bash
pip install -r requirements.txt          # one file now covers CLI + web (httpx + Flask)
python3 web/app.py                        # → http://127.0.0.1:5000
# custom port:
PQC_WEB_PORT=8080 python3 web/app.py
```

> Install into the **same interpreter** you launch `web/app.py` with — scans run
> as a subprocess of that Python (`sys.executable`), so both `httpx` and `Flask`
> must live in one environment. If `python3` is a pyenv/venv shim, run the
> `pip install` with that exact `python3`.

Then open the URL, paste a repo/path, click **Detect library**, and **Run scan**.

A scan needs whatever the CLI needs: `rg` on PATH, plus a running Ollama server
(default backend) or `ANTHROPIC_API_KEY` in the environment for `--backend
anthropic`. Start the server from the repo root (or via `web/app.py`, which sets
the working directory correctly) so `runs/`, `libraries/`, and `main.py` resolve.

## Notes / scope

- **Local, single-user tool.** It binds to `127.0.0.1` and has no auth — don't
  expose it to a network. Flask's dev server is fine for local use.
- **Job state is in memory**; the durable record is `runs/` on disk, so the
  history and result pages survive a restart. Only the live progress of an
  in-flight scan is lost if you restart the server mid-scan.
- **GitHub clones** land in `web/workspaces/` (git-ignored). They accumulate
  across scans — prune them with **"Clear all runs & clones"** on the history
  page. Local-folder scans are zero-copy (nothing lands here).
- Path traversal is guarded on every file-serving route; artifact serving is
  whitelisted to `report.{html,md,json}`, `run.log`, `run.json`.

## Files

```
web/
  app.py         Flask routes (pages + JSON APIs)
  detect.py      library auto-detection (entry-point grep + ranking)
  runner.py      background scan jobs (clone + subprocess wrapper over main.py)
  scans.py       read/parse runs/ into history + detail views; delete/clear
  templates/     index (submit) · scans (history) · detail (result)
  static/        style.css · app.js
  workspaces/    cloned GitHub targets (git-ignored)
```
