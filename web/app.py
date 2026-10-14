"""Flask frontend for the PQC Vulnerability Assessor.

A thin web layer over the existing CLI. Three things it adds:
  1. A submit page — GitHub URL, a local path, or drag-and-drop upload.
  2. Auto-detection of the library from the target's own symbols.
  3. A history browser + result viewer over runs/.

Run:  python3 web/app.py         (then open http://127.0.0.1:5000)
It shells out to `main.py` for the actual scan, so everything the CLI produces
(run.log, run.json, report.{html,md,json}) is produced here too.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import httpx
from flask import (Flask, jsonify, render_template, request,
                   send_file, abort, url_for)

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import config  # noqa: E402
from core.tools import tool_status  # noqa: E402
from core.llm import ANTHROPIC_MODELS_URL, ANTHROPIC_VERSION  # noqa: E402
from web import detect, runner, scans, libeditor, pocs  # noqa: E402

app = Flask(__name__)
# Jinja caches compiled templates when debug is off (which it is — see __main__),
# so a template edit needs a full restart to show up. This is a local single-user
# tool, so re-check the mtime instead: an edited page appears on the next reload.
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.auto_reload = True


def _anthropic_model_catalog(api_key: str) -> list[dict[str, str]]:
    """Return models available to this Anthropic API key, newest first."""
    response = httpx.get(
        ANTHROPIC_MODELS_URL,
        headers={
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_VERSION,
        },
        params={"limit": 1000},
        timeout=8.0,
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("Anthropic model response must be an object")

    catalog = []
    seen = set()
    for item in payload.get("data", []):
        if not isinstance(item, dict):
            continue
        model_id = item.get("id")
        if not isinstance(model_id, str) or not model_id or model_id in seen:
            continue
        seen.add(model_id)
        display_name = item.get("display_name")
        catalog.append({
            "id": model_id,
            "display_name": (display_name
                             if isinstance(display_name, str) and display_name
                             else model_id),
            "created_at": (item.get("created_at")
                           if isinstance(item.get("created_at"), str)
                           else ""),
        })
    return catalog


# ------------------------------------------------------------------ pages
@app.route("/")
def index():
    return render_template("index.html",
                           libraries=config.library_names(),
                           modes=runner.MODES,
                           backends=runner.BACKENDS)


@app.route("/scans")
def scans_page():
    return render_template("scans.html", runs=scans.list_runs())


@app.route("/scan/<library>/<timestamp>")
def detail_page(library, timestamp):
    detail = scans.run_detail(f"{library}/{timestamp}")
    if not detail:
        abort(404)
    return render_template("detail.html", run=detail)


@app.route("/libraries")
def libraries_page():
    return render_template("libraries.html",
                           libraries=libeditor.list_libraries(),
                           langs=sorted(config.LANG_GLOBS))


# ------------------------------------------------------------------- PoCs
@app.route("/pocs")
def pocs_page():
    """Every run PoCs can exist for, newest first — including ones with none
    yet, so they can be generated without re-scanning."""
    return render_template("pocs.html", runs=pocs.runs_for_poc())


@app.route("/scan/<library>/<timestamp>/poc")
def poc_run_page(library, timestamp):
    """The PoC packages belonging to one run."""
    run_id = f"{library}/{timestamp}"
    detail = scans.run_detail(run_id)
    if not detail:
        abort(404)
    return render_template("poc_run.html", run=detail,
                           packages=pocs.list_packages(run_id),
                           backends=runner.BACKENDS)


@app.route("/scan/<library>/<timestamp>/poc/<poc_id>")
def poc_detail_page(library, timestamp, poc_id):
    """One PoC package: README, drafted sources, build script."""
    run_id = f"{library}/{timestamp}"
    pkg = pocs.package_detail(run_id, poc_id)
    if not pkg:
        abort(404)
    return render_template("poc_detail.html", run_id=run_id, library=library,
                           timestamp=timestamp, pkg=pkg)


# ------------------------------------------------------------------- APIs
@app.route("/api/libraries")
def api_libraries():
    return jsonify(config.library_names())


@app.route("/api/libraries/list")
def api_libraries_list():
    return jsonify(libeditor.list_libraries())


@app.route("/api/libraries/<name>/raw")
def api_library_raw(name):
    content = libeditor.read_library(name)
    if content is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({"name": name, "content": content})


@app.route("/api/libraries/template")
def api_library_template():
    return jsonify({"content": libeditor.new_template(request.args.get("name", ""))})


@app.route("/api/libraries/validate", methods=["POST"])
def api_library_validate():
    data = request.get_json(force=True, silent=True) or {}
    ok, err = libeditor.validate(data.get("content", ""))
    return jsonify({"ok": ok, "error": err})


@app.route("/api/libraries/<name>", methods=["POST"])
def api_library_save(name):
    data = request.get_json(force=True, silent=True) or {}
    ok, err = libeditor.save_library(name, data.get("content", ""))
    return (jsonify({"ok": True}) if ok else (jsonify({"ok": False, "error": err}), 400))


@app.route("/api/libraries/<name>/delete", methods=["POST"])
def api_library_delete(name):
    ok, err = libeditor.delete_library(name)
    return (jsonify({"ok": True}) if ok else (jsonify({"ok": False, "error": err}), 404))


@app.route("/api/doctor")
def api_doctor():
    lib = request.args.get("library", "")
    spec = config.get_library(lib)
    lang = spec.lang if spec else "c"
    return jsonify({"library": lib, "lang": lang, "tools": tool_status(lang)})


@app.route("/api/env")
def api_env():
    """Report whether the Anthropic key is present in the server environment —
    the boolean only, never the value. The web layer never handles the key
    itself; the scan subprocess reads it from the inherited environment."""
    return jsonify({"anthropic_key_set": bool(os.environ.get("ANTHROPIC_API_KEY"))})


@app.route("/api/backend-check")
def api_backend_check():
    """Is the chosen backend actually usable right now? Prevents the #1 silent
    failure — clicking Run scan with Ollama not running, or Anthropic with no
    key. Returns {ready, message, models, detail?}."""
    backend = request.args.get("backend", "ollama")
    if backend == "anthropic":
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            return jsonify({
                "backend": backend,
                "ready": False,
                "models": [],
                "model_options": [],
                "message": ("ANTHROPIC_API_KEY not set — export it and "
                            "restart the app"),
            })
        try:
            catalog = _anthropic_model_catalog(api_key)
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            message = (f"Anthropic rejected the model-list request (HTTP {status})"
                       if status in (401, 403)
                       else f"Anthropic model discovery failed (HTTP {status})")
            return jsonify({
                "backend": backend,
                "ready": False,
                "models": [],
                "model_options": [],
                "message": message,
            })
        except (httpx.HTTPError, ValueError, TypeError):
            return jsonify({
                "backend": backend,
                "ready": False,
                "models": [],
                "model_options": [],
                "message": "Could not reach Anthropic to load available models",
            })

        if not catalog:
            return jsonify({
                "backend": backend,
                "ready": False,
                "models": [],
                "model_options": [],
                "message": "Anthropic is reachable, but no models are available to this API key",
            })

        model_ids = [model["id"] for model in catalog]
        return jsonify({
            "backend": backend,
            "ready": True,
            "models": model_ids,
            "model_options": catalog,
            "default_model": model_ids[0],
            "message": f"Anthropic reachable · {len(catalog)} model(s) available",
            "detail": model_ids[:8],
        })
    # ollama: probe the same endpoint the scanner uses (/api/tags).
    base = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    try:
        r = httpx.get(f"{base}/api/tags", timeout=3.0)
        models = [m.get("name") for m in (r.json().get("models") or [])]
        if not models:
            return jsonify({"backend": backend, "ready": True,
                            "models": [],
                            "message": f"Ollama is running at {base}, but no models are pulled "
                                       "(e.g. `ollama pull deepseek-r1:14b`)"})
        return jsonify({"backend": backend, "ready": True,
                        "models": models,
                        "message": f"Ollama reachable at {base} · {len(models)} model(s)",
                        "detail": models[:8]})
    except Exception:
        return jsonify({"backend": backend, "ready": False,
                        "models": [],
                        "message": f"Ollama not reachable at {base} — start it (`ollama serve`)"})


@app.route("/api/browse", methods=["POST"])
def api_browse():
    """Open a native folder-picker ON THE SERVER (this is a local tool, so the
    server and the browser are the same machine) and return the chosen absolute
    path. Fixes the browser limitation where a picked folder yields only its
    name. Runs the picker as a subprocess so tkinter stays out of Flask's
    worker threads."""
    import subprocess
    script = _REPO_ROOT / "web" / "pick_folder.py"
    try:
        r = subprocess.run([sys.executable, str(script)],
                           capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return jsonify({"error": "folder dialog timed out"}), 504
    if r.returncode != 0:
        return jsonify({"error": "no folder dialog available on this machine — "
                        "type or paste the path instead",
                        "detail": (r.stderr or "").strip()[:200]}), 501
    path = (r.stdout or "").strip()
    if not path:
        return jsonify({"cancelled": True})
    return jsonify({"path": path})


@app.route("/api/resolve-path", methods=["POST"])
def api_resolve_path():
    """Resolve a dropped file/folder name or raw path string to an absolute path on disk.
    Works seamlessly across Mac, Windows, and Linux."""
    import urllib.parse
    data = request.get_json(force=True, silent=True) or {}
    raw = (data.get("path") or data.get("name") or "").strip().strip("'\"")
    if not raw:
        return jsonify({"error": "no path or name provided"}), 400

    clean = raw
    if clean.lower().startswith("file://"):
        clean = clean[7:]
        if clean.lower().startswith("localhost/"):
            clean = clean[10:]
        clean = urllib.parse.unquote(clean)
        if len(clean) >= 3 and clean[0] == "/" and clean[2] == ":":
            clean = clean[1:]

    # 1. Direct path resolution
    try:
        p = Path(clean).expanduser().resolve()
        if p.exists():
            target = p if p.is_dir() else p.parent
            return jsonify({"path": str(target), "found": True, "is_file": p.is_file()})
    except Exception:
        pass

    # 2. Search common user directories for matching folder/file name
    base_name = Path(clean).name
    candidate_bases = [
        Path.cwd(),
        Path.home(),
        Path.home() / "Desktop",
        Path.home() / "Downloads",
        Path.home() / "Documents",
        Path.home() / "Projects",
        Path.home() / "workspace",
        Path.home() / "code",
        Path.cwd().parent,
    ]
    for base in candidate_bases:
        try:
            if not base.is_dir():
                continue
            cand = base / base_name
            if cand.exists():
                target = cand if cand.is_dir() else cand.parent
                return jsonify({"path": str(target.resolve()), "found": True, "is_file": cand.is_file()})
        except Exception:
            continue

    return jsonify({"path": clean, "found": False})


@app.route("/api/github-tags", methods=["POST"])
def api_github_tags():
    import subprocess
    data = request.get_json(force=True, silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url or not runner._GITHUB_RE.match(url):
        return jsonify({"tags": []})
    try:
        r = subprocess.run(["git", "ls-remote", "--tags", "--refs", url],
                           capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            return jsonify({"tags": []})
        tags = []
        for line in r.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) == 2 and parts[1].startswith("refs/tags/"):
                tags.append(parts[1].replace("refs/tags/", ""))
        tags.reverse()
        return jsonify({"tags": tags[:30]})
    except Exception:
        return jsonify({"tags": []})


@app.route("/api/detect", methods=["POST"])
def api_detect():
    import urllib.parse
    data = request.get_json(force=True, silent=True) or {}
    kind = data.get("source_kind")
    source = (data.get("source") or "").strip()
    if not source:
        return jsonify({"error": "no source provided"}), 400
    try:
        if kind == "github":
            git_ref = (data.get("git_ref") or "").strip() or None
            # Clone shallowly so detection can inspect real symbols, then reuse
            # that same checkout for the scan by returning its path.
            job = runner.Job("_detect", "reason", "ollama", None, False, "github", source, git_ref=git_ref)
            path = job._clone_github(source, git_ref=git_ref)
        elif kind in ("path", "upload"):
            clean_source = source.strip("'\"")
            if clean_source.lower().startswith("file://"):
                clean_source = clean_source[7:]
                if clean_source.lower().startswith("localhost/"):
                    clean_source = clean_source[10:]
                clean_source = urllib.parse.unquote(clean_source)
                if len(clean_source) >= 3 and clean_source[0] == "/" and clean_source[2] == ":":
                    clean_source = clean_source[1:]
            path = Path(clean_source).expanduser().resolve()
            if path.is_file():
                path = path.parent
            if not path.is_dir():
                return jsonify({"error": f"directory not found: {path}"}), 400
        else:
            return jsonify({"error": "unknown source_kind"}), 400
        result = detect.detect_library(path)
        result["resolved_path"] = str(path)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 400


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(force=True, silent=True) or {}
    try:
        poc_rounds = int(data.get("poc_compile_rounds") or 0)
    except (TypeError, ValueError):
        return jsonify({"error": "PoC compile rounds must be a whole number"}), 400
    try:
        job = runner.start_job(
            library=data["library"],
            mode=data.get("mode", "agent-review"),
            backend=data.get("backend", "ollama"),
            model=data.get("model") or None,
            reviewer_model=data.get("reviewer_model") or None,
            explain=bool(data.get("explain")),
            source_kind=data["source_kind"],
            source=data["source"],
            discovery_passes=data.get("discovery_passes") or None,
            git_ref=(data.get("git_ref") or "").strip() or None,
            poc=bool(data.get("poc")),
            poc_drafter_model=data.get("poc_drafter_model") or None,
            poc_critic_model=data.get("poc_critic_model") or None,
            poc_compile_rounds=poc_rounds,
        )
    except (KeyError, ValueError, TypeError) as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(job.to_dict())


@app.route("/api/job/<job_id>")
def api_job(job_id):
    job = runner.get_job(job_id)
    if not job:
        return jsonify({"error": "unknown job"}), 404
    return jsonify(job.to_dict())


@app.route("/api/job/<job_id>/cancel", methods=["POST"])
def api_job_cancel(job_id):
    job = runner.get_job(job_id)
    if not job:
        return jsonify({"error": "unknown job"}), 404
    return jsonify({"cancelled": job.cancel()})


@app.route("/api/jobs")
def api_jobs():
    return jsonify(runner.active_jobs())


@app.route("/api/scans")
def api_scans():
    return jsonify(scans.list_runs())


@app.route("/api/scan/<library>/<timestamp>")
def api_scan_detail(library, timestamp):
    detail = scans.run_detail(f"{library}/{timestamp}")
    if not detail:
        return jsonify({"error": "not found"}), 404
    return jsonify(detail)


@app.route("/api/scan/<library>/<timestamp>/delete", methods=["POST"])
def api_scan_delete(library, timestamp):
    ok = scans.delete_run(f"{library}/{timestamp}")
    if not ok:
        return jsonify({"error": "not found"}), 404
    return jsonify({"deleted": True})


@app.route("/api/scans/clear", methods=["POST"])
def api_scans_clear():
    """Clear the memory of all old runs: every run dir under runs/ plus the
    cached repo clones/uploads in web/workspaces/ (except any active scan's)."""
    runs_deleted = scans.delete_all()
    ws = runner.clear_workspaces()
    return jsonify({"runs": runs_deleted, "workspaces": ws})


@app.route("/api/pocs")
def api_pocs():
    return jsonify(pocs.runs_with_pocs())


@app.route("/api/scan/<library>/<timestamp>/pocs/generate", methods=["POST"])
def api_generate_pocs(library, timestamp):
    """Generate PoC packages for a finished run, without re-scanning."""
    data = request.get_json(force=True, silent=True) or {}
    try:
        rounds = int(data.get("poc_compile_rounds") or 0)
    except (TypeError, ValueError):
        return jsonify({"error": "PoC compile rounds must be a whole number"}), 400
    try:
        job = runner.start_poc_job(
            f"{library}/{timestamp}",
            drafter_model=data.get("poc_drafter_model") or None,
            critic_model=data.get("poc_critic_model") or None,
            compile_rounds=rounds,
            overwrite=bool(data.get("overwrite", True)),
        )
    except (KeyError, ValueError, TypeError) as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(job.to_dict())


@app.route("/api/scan/<library>/<timestamp>/pocs")
def api_run_pocs(library, timestamp):
    return jsonify(pocs.list_packages(f"{library}/{timestamp}"))


@app.route("/api/scan/<library>/<timestamp>/poc/<poc_id>")
def api_poc_detail(library, timestamp, poc_id):
    pkg = pocs.package_detail(f"{library}/{timestamp}", poc_id)
    if not pkg:
        return jsonify({"error": "not found"}), 404
    return jsonify(pkg)


@app.route("/scan/<library>/<timestamp>/poc/<poc_id>/file/<name>")
def poc_file(library, timestamp, poc_id, name):
    """Download one file out of a PoC package. Always an attachment — these are
    sources and shell scripts meant to be built locally, never rendered."""
    p = pocs.poc_file(f"{library}/{timestamp}", poc_id, name)
    if not p:
        abort(404)
    return send_file(p, as_attachment=True,
                     mimetype="text/plain; charset=utf-8",
                     download_name=f"{poc_id}-{name}")


@app.route("/scan/<library>/<timestamp>/poc/<poc_id>/download")
def poc_download_zip(library, timestamp, poc_id):
    """The whole PoC package as a zip — what you actually want before building."""
    import io
    import zipfile
    run_id = f"{library}/{timestamp}"
    pkg = pocs.package_detail(run_id, poc_id)
    if not pkg:
        abort(404)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in pkg["files"]:
            p = pocs.poc_file(run_id, poc_id, f["name"])
            if p:
                z.write(p, arcname=f"{poc_id}/{f['name']}")
    buf.seek(0)
    return send_file(buf, mimetype="application/zip", as_attachment=True,
                     download_name=f"{library}-{timestamp}-{poc_id}.zip")


@app.route("/scan/<library>/<timestamp>/file/<name>")
def scan_file(library, timestamp, name):
    p = scans.run_file(f"{library}/{timestamp}", name)
    if not p:
        abort(404)
    # report.html is rendered inline; everything else downloads/plain.
    as_attach = name not in ("report.html",)
    # charset=utf-8 so the browser renders UTF-8 logs/markdown correctly instead
    # of guessing (and mangling arrows/box glyphs/✓ as cp1252/latin-1).
    mime = "text/plain; charset=utf-8" if name.endswith((".log", ".md")) else None
    return send_file(p, as_attachment=as_attach, mimetype=mime,
                     download_name=f"{library}-{timestamp}-{name}")


if __name__ == "__main__":
    # Windows consoles default to cp1252, which cannot encode the arrows/✓ this
    # app prints (and the startup banner below dies before Flask ever binds).
    # Force UTF-8 on our own streams rather than degrading the messages.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    port = int(__import__("os").environ.get("PQC_WEB_PORT", "5000"))
    # Preflight: scans run as a subprocess of THIS interpreter (sys.executable),
    # so it must be able to import httpx (the scanner's one hard dep). Catch a
    # flask-but-no-httpx environment here with a clear fix instead of letting
    # every scan fail with a traceback buried in run.log.
    import importlib.util
    if importlib.util.find_spec("httpx") is None:
        print(
            "\n  ERROR: this Python is missing 'httpx', which the scanner needs.\n"
            f"  Interpreter: {sys.executable}\n"
            "  Scans launch as a subprocess of THIS interpreter, so install the\n"
            "  scanner deps into it (not just Flask):\n\n"
            f"      {sys.executable} -m pip install -r requirements.txt\n\n"
            "  …or start the UI with a Python that already has httpx, e.g.\n"
            "      /usr/bin/python3 web/app.py\n",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"PQC Assessor web UI → http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
