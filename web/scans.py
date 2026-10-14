"""Read and summarise past scans from runs/<lib>/<ts>/.

The runs/ directory is the single source of truth (written by the CLI). Each run
dir may contain: run.json (manifest), report.json (full result), report.html /
report.md (rendered), run.log (console log). This module turns those into
JSON-serialisable summaries for the history list and detail views.
"""
from __future__ import annotations

import json
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = _REPO_ROOT / "runs"

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _read_json(p: Path) -> dict:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _run_id(run_dir: Path) -> str:
    """Stable id for URLs: '<library>/<timestamp>'."""
    return f"{run_dir.parent.name}/{run_dir.name}"


def summarise_run(run_dir: Path) -> dict | None:
    """One run -> a compact summary dict for the history list."""
    if not run_dir.is_dir():
        return None
    manifest = _read_json(run_dir / "run.json")
    report = _read_json(run_dir / "report.json")
    if not manifest and not report:
        # A run dir with neither manifest nor report (e.g. crashed very early).
        if not (run_dir / "run.log").exists():
            return None

    summary = report.get("summary", {}) or {}
    findings = report.get("findings", []) or []
    sev_counts = {s: int(summary.get(s, 0)) for s in _SEV_ORDER}
    top_sev = next((s for s in _SEV_ORDER if sev_counts.get(s)), None)

    return {
        "id": _run_id(run_dir),
        "library": run_dir.parent.name,
        "timestamp": run_dir.name,
        "target": manifest.get("target") or report.get("target"),
        "target_git_commit": manifest.get("target_git_commit"),
        "mode": manifest.get("mode"),
        "backend": manifest.get("backend"),
        "model": manifest.get("model"),
        "started": manifest.get("started"),
        "duration_seconds": manifest.get("duration_seconds")
                            or report.get("duration_seconds"),
        "interrupted": bool(manifest.get("interrupted")),
        "findings_total": len(findings),
        "findings_confirmed": manifest.get("findings_confirmed"),
        "severity_counts": sev_counts,
        "top_severity": top_sev,
        "has_report_html": (run_dir / "report.html").exists(),
        "has_log": (run_dir / "run.log").exists(),
        "stage_timings": manifest.get("stage_timings", []),
    }


def list_runs() -> list[dict]:
    """All runs across all libraries, newest first."""
    if not RUNS_DIR.is_dir():
        return []
    out = []
    for lib_dir in RUNS_DIR.iterdir():
        if not lib_dir.is_dir():
            continue
        for run_dir in lib_dir.iterdir():
            if run_dir.is_symlink() or not run_dir.is_dir():
                continue  # skip the 'latest' symlink
            s = summarise_run(run_dir)
            if s:
                out.append(s)
    out.sort(key=lambda r: r["timestamp"], reverse=True)
    return out


def _resolve_dir(run_id: str) -> Path | None:
    """Map a '<library>/<timestamp>' id back to a run dir, guarding traversal."""
    parts = [p for p in run_id.replace("\\", "/").split("/") if p and p not in ("..", ".")]
    if len(parts) != 2:
        return None
    d = (RUNS_DIR / parts[0] / parts[1]).resolve()
    if RUNS_DIR.resolve() not in d.parents:
        return None
    return d if d.is_dir() else None


def run_detail(run_id: str) -> dict | None:
    """Full detail for one run: manifest + report + coverage + findings."""
    run_dir = _resolve_dir(run_id)
    if not run_dir:
        return None
    manifest = _read_json(run_dir / "run.json")
    report = _read_json(run_dir / "report.json")
    summ = summarise_run(run_dir) or {}
    # Counted here rather than via web.pocs so this module stays import-free of
    # the PoC layer (web.pocs reads scans, not the other way round).
    poc_root = run_dir / "poc"
    try:
        poc_count = sum(1 for d in poc_root.iterdir() if d.is_dir()) \
            if poc_root.is_dir() else 0
    except OSError:
        poc_count = 0
    summ.update({
        "manifest": manifest,
        "coverage": report.get("coverage", {}),
        "triage": report.get("triage", []),
        "findings": report.get("findings", []),
        "validation_status": report.get("validation_status", {}),
        "poc_count": poc_count,
    })
    return summ


def delete_run(run_id: str) -> bool:
    """Delete one run dir (guarded against traversal). Fixes the parent's
    `latest` symlink if it pointed at the deleted run, and removes the library
    dir if it becomes empty. Returns True if something was deleted."""
    import shutil
    run_dir = _resolve_dir(run_id)
    if not run_dir:
        return False
    lib_dir = run_dir.parent
    latest = lib_dir / "latest"
    # Drop a dangling/now-wrong 'latest' before removing the target.
    try:
        if latest.is_symlink() and (lib_dir / latest.readlink()).resolve() == run_dir.resolve():
            latest.unlink()
    except OSError:
        pass
    shutil.rmtree(run_dir, ignore_errors=True)
    # Repoint 'latest' at the newest remaining run, or tidy up an empty lib dir.
    remaining = [d for d in lib_dir.iterdir()
                 if d.is_dir() and not d.is_symlink()] if lib_dir.exists() else []
    if remaining:
        newest = max(remaining, key=lambda d: d.name)
        try:
            if latest.is_symlink() or latest.exists():
                latest.unlink()
            latest.symlink_to(newest.name)
        except OSError:
            pass
    else:
        # No runs left: remove the stray 'latest' and the empty library dir.
        try:
            if latest.is_symlink() or latest.exists():
                latest.unlink()
            if lib_dir.exists() and not any(lib_dir.iterdir()):
                lib_dir.rmdir()
        except OSError:
            pass
    return True


def delete_all() -> int:
    """Delete every run across all libraries. Returns count deleted."""
    n = 0
    for r in list_runs():
        if delete_run(r["id"]):
            n += 1
    return n


def run_file(run_id: str, name: str) -> Path | None:
    """Resolve a named artifact (report.html / run.log / run.json / report.md)
    inside a run dir, guarding against path traversal."""
    allowed = {"report.html", "report.md", "report.json", "run.log", "run.json"}
    if name not in allowed:
        return None
    run_dir = _resolve_dir(run_id)
    if not run_dir:
        return None
    p = run_dir / name
    return p if p.is_file() else None
