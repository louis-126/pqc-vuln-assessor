"""Read PoC packages produced by a scan from runs/<lib>/<ts>/poc/<FINDING-ID>/.

The pipeline's PoC stage (pipeline._generate_pocs -> poc.generator.
generate_poc_package) writes one directory per confirmed finding, containing a
README.md plus — for C targets — server.c / client.c / poc_net.h / build.sh.
Nothing is compiled or run by the assessor; the package is for the user to
build themselves.

This module is the read side only: it turns those directories into
JSON-serialisable summaries for the web UI, and resolves individual files for
viewing/download with the same traversal guarding scans.py uses. It never
writes to runs/.
"""
from __future__ import annotations

import json
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = _REPO_ROOT / "runs"

# Files a PoC package may expose. Extension-based rather than name-based so the
# Java emit path (Demo*.java, build.bat) needs no change here, while still
# refusing anything unexpected that lands in the directory.
_VIEWABLE_SUFFIXES = {".md", ".c", ".h", ".java", ".sh", ".bat", ".txt", ".json", ".xml"}

# Rendered as text in the browser; everything else downloads.
_TEXT_SUFFIXES = _VIEWABLE_SUFFIXES

_CODE_SUFFIXES = {".c", ".h", ".java"}
# Fixed, generator-owned transport files — never model-drafted.
_TRANSPORT = {"poc_net.h", "PocNet.java"}


def _read_json(p: Path) -> dict:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _resolve_run(run_id: str) -> Path | None:
    """Map '<library>/<timestamp>' to a run dir, guarding traversal."""
    parts = [p for p in run_id.replace("\\", "/").split("/")
             if p and p not in ("..", ".")]
    if len(parts) != 2:
        return None
    d = (RUNS_DIR / parts[0] / parts[1]).resolve()
    if RUNS_DIR.resolve() not in d.parents:
        return None
    return d if d.is_dir() else None


def _infer_status(files: list[str]) -> str:
    """Mirror generate_poc_package's own status vocabulary from what it wrote.

    The generator returns status in-process but does not persist it, so the
    file set is the durable signal: it writes README.md always, and one code
    file per role it managed to draft.
    """
    # Both languages are client/server pairs now, so the rule is the same for
    # each: count the DRAFTED sources and ignore the fixed transport, which is
    # copied verbatim and proves nothing about what the model managed to write.
    code = [f for f in files if Path(f).suffix in _CODE_SUFFIXES
            and Path(f).name not in _TRANSPORT]
    if len(code) >= 2:
        return "generated"
    if len(code) == 1:
        return "partial"
    return "doc_only"


def _findings_index(run_dir: Path) -> dict[str, dict]:
    """Finding metadata from report.json, keyed by finding id, so a PoC package
    can be shown with its title/severity/CWE rather than a bare directory name."""
    report = _read_json(run_dir / "report.json")
    out = {}
    for f in report.get("findings", []) or []:
        fid = f.get("id")
        if fid:
            out[fid] = {
                "title": f.get("title"),
                "severity": f.get("severity"),
                "cwe": f.get("cwe"),
                "file": f.get("file"),
                "entry_point": f.get("entry_point"),
                "confidence": f.get("confidence"),
            }
    return out


def _describe_package(poc_dir: Path, meta: dict | None) -> dict:
    files = []
    for p in sorted(poc_dir.iterdir()):
        if not p.is_file():
            continue
        files.append({
            "name": p.name,
            "size": p.stat().st_size,
            "viewable": p.suffix in _VIEWABLE_SUFFIXES,
        })
    names = [f["name"] for f in files]
    return {
        "id": poc_dir.name,
        "status": _infer_status(names),
        "files": files,
        "file_count": len(files),
        "has_readme": "README.md" in names,
        "has_build": any(n in ("build.sh", "build.bat") for n in names),
        "finding": meta or {},
    }


def list_packages(run_id: str) -> list[dict]:
    """Every PoC package in one run, ordered by finding id."""
    run_dir = _resolve_run(run_id)
    if not run_dir:
        return []
    poc_root = run_dir / "poc"
    if not poc_root.is_dir():
        return []
    index = _findings_index(run_dir)
    out = [_describe_package(d, index.get(d.name))
           for d in sorted(poc_root.iterdir()) if d.is_dir()]
    return out


def package_count(run_id: str) -> int:
    """Cheap existence check for the run detail page's PoC tab."""
    run_dir = _resolve_run(run_id)
    if not run_dir:
        return 0
    poc_root = run_dir / "poc"
    if not poc_root.is_dir():
        return 0
    return sum(1 for d in poc_root.iterdir() if d.is_dir())


def runs_for_poc() -> list[dict]:
    """Every run that COULD have packages — i.e. has a report.json — newest
    first, each annotated with poc_count. Runs with none are still listed so
    they can be generated for without a re-scan.
    """
    from web import scans
    out = []
    for r in scans.list_runs():
        run_dir = _resolve_run(r["id"])
        if not run_dir or not (run_dir / "report.json").is_file():
            continue
        r = dict(r)
        r["poc_count"] = package_count(r["id"])
        out.append(r)
    return out


def runs_with_pocs() -> list[dict]:
    """All runs that produced at least one PoC package, newest first.

    Imported lazily from scans to reuse its run summaries without creating a
    circular import at module load.
    """
    from web import scans
    out = []
    for r in scans.list_runs():
        n = package_count(r["id"])
        if n:
            r = dict(r)
            r["poc_count"] = n
            out.append(r)
    return out


def package_detail(run_id: str, poc_id: str) -> dict | None:
    """One PoC package, with the text of every viewable file inlined so the
    detail page can render it without a request per file."""
    run_dir = _resolve_run(run_id)
    if not run_dir:
        return None
    poc_dir = _safe_poc_dir(run_dir, poc_id)
    if not poc_dir:
        return None
    detail = _describe_package(poc_dir, _findings_index(run_dir).get(poc_dir.name))
    contents = {}
    for f in detail["files"]:
        if not f["viewable"]:
            continue
        p = poc_dir / f["name"]
        try:
            contents[f["name"]] = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            contents[f["name"]] = ""
    detail["contents"] = contents
    detail["run_id"] = run_id
    return detail


def _safe_poc_dir(run_dir: Path, poc_id: str) -> Path | None:
    """Resolve one package dir, refusing traversal out of runs/<lib>/<ts>/poc."""
    if not poc_id or "/" in poc_id or "\\" in poc_id or poc_id in ("..", "."):
        return None
    poc_root = (run_dir / "poc").resolve()
    d = (poc_root / poc_id).resolve()
    if poc_root not in d.parents:
        return None
    return d if d.is_dir() else None


def poc_file(run_id: str, poc_id: str, name: str) -> Path | None:
    """Resolve one file inside a PoC package for download, guarded against
    traversal and restricted to the known-safe suffix set."""
    if not name or "/" in name or "\\" in name or name in ("..", "."):
        return None
    if Path(name).suffix not in _VIEWABLE_SUFFIXES:
        return None
    run_dir = _resolve_run(run_id)
    if not run_dir:
        return None
    poc_dir = _safe_poc_dir(run_dir, poc_id)
    if not poc_dir:
        return None
    p = (poc_dir / name).resolve()
    if poc_dir not in p.parents:
        return None
    return p if p.is_file() else None


def is_text(name: str) -> bool:
    return Path(name).suffix in _TEXT_SUFFIXES
