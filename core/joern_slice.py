"""core/joern_slice.py — Code Property Graph (CPG) slicing via Joern.

Optional robust-tooling tier (v3 stage 4). When Joern is installed, this gives
the investigator data-flow slices that span multiple functions/files around
crypto-relevant sinks (division/modulo for KyberSlash-class timing bugs,
memcmp/comparison on secrets, array indexing by secret, RNG calls). This
catches multi-function vulnerabilities that fixed-window file reads miss.

Based on the LLMxCPG approach (USENIX Security 2025): CPG slicing reduces code
size 68-91% while preserving vulnerability-relevant context, letting a
context-limited local model reason about whole-project data flows.

Graceful fallback: if `joern` / `joern-slice` is not on PATH, the tool registers
but every call returns a one-line "not installed" message, and the rest of the
pipeline (ripgrep + entry points) continues unchanged. A missing Joern install
never breaks a run.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

log = logging.getLogger("pqc.joern")

# Availability probed once at import. CPG slicing needs ALL THREE binaries:
# `joern-parse` to build the CPG and `joern-slice` to slice it. A partial
# install (e.g. `joern` present but `joern-slice` missing) was the trigger that
# let a runtime error string leak into the model's evidence and become a false
# finding — so availability now requires the binaries we actually invoke.
_JOERN_AVAILABLE = shutil.which("joern") is not None
_JOERN_SLICE_AVAILABLE = shutil.which("joern-slice") is not None
_JOERN_PARSE_AVAILABLE = shutil.which("joern-parse") is not None

# Uniform sentinel for every failure/skip path. It contains NO file paths, NO
# stderr, and NO analyzable content, so the model cannot mistake a plumbing
# error for a code issue (the FND-"Missing CPG File" false-finding class). The
# investigator prompt already treats a leading "[skip]" as "no data — ignore".
_SKIP = "[skip] CPG slicing produced no data; ignore this and use read_file/search_code."

if not _JOERN_AVAILABLE:
    log.warning("'joern' not in PATH — CPG slicing unavailable (falling back to ripgrep)")

# Crypto-relevant sink patterns for PQC data-flow slicing.
# joern-slice --sink-filter takes a regex matched against the sink's `code`.
_PQC_SINK_FILTERS = {
    "division": r"/|%|div|mod|barrett|montgomery|reduce",   # KyberSlash class
    "comparison": r"memcmp|XMEMCMP|==|!=|ConstantCompare",   # FO check / verify
    "rng": r"rand|RAND|GenerateSeed|srand|seed",             # weak RNG
    "index": r"\[",                                          # secret-indexed array
}


def _joern_workdir() -> str:
    """Dedicated temp dir so any stray artifacts Joern drops in the CWD
    (cpg.bin, workspace/) land here, NOT in the user's project tree where the
    model would mistake cpg.bin for a source file and invent findings on it."""
    d = Path(tempfile.gettempdir()) / "pqc_joern"
    d.mkdir(exist_ok=True)
    return str(d)


def joern_available() -> bool:
    """All three binaries the pipeline actually invokes must be present, not
    just `joern` — otherwise a partial install passes the gate and then fails
    mid-slice, leaking an error string into the evidence."""
    return (_JOERN_AVAILABLE and _JOERN_PARSE_AVAILABLE
            and _JOERN_SLICE_AVAILABLE)


def joern_enabled() -> bool:
    """Default-OFF gate. Joern's CLI contract (flag names, slice JSON shape) is
    unverified against the installed version and its sink filters are imprecise,
    so it is opt-in until validated on the host: set PQC_ENABLE_JOERN=1. This
    keeps a possibly-broken Joern entirely off the default evidence path."""
    return joern_available() and os.environ.get("PQC_ENABLE_JOERN", "") == "1"


class _CpgCache:
    """Caches the built CPG path per target tree so we build it at most once."""
    _paths: dict[str, str] = {}

    @classmethod
    def get(cls, target: str) -> str | None:
        return cls._paths.get(target)

    @classmethod
    def set(cls, target: str, cpg_path: str) -> None:
        cls._paths[target] = cpg_path


def _build_cpg(target: str, timeout: int = 600) -> str | None:
    """Build (or reuse) a CPG binary for the target tree. Returns path or None."""
    cached = _CpgCache.get(target)
    if cached and Path(cached).exists():
        return cached

    if not _JOERN_PARSE_AVAILABLE:
        return None

    # Stable digest (NOT hash() — that is randomized per process, so the on-disk
    # CPG was never reused across runs and got rebuilt every time).
    digest = hashlib.sha1(str(Path(target).resolve()).encode()).hexdigest()[:16]
    cpg_path = str(Path(tempfile.gettempdir()) / f"pqc_cpg_{digest}.bin")
    log.info("[joern] building CPG for %s (one-time, may take minutes)...", target)
    try:
        r = subprocess.run(
            ["joern-parse", target, "--output", cpg_path],
            capture_output=True, text=True, timeout=timeout,
            cwd=_joern_workdir(),
        )
        if r.returncode != 0:
            log.warning("[joern] joern-parse failed: %s", r.stderr[:300])
            return None
    except subprocess.TimeoutExpired:
        log.warning("[joern] CPG build timed out after %ds", timeout)
        return None
    except Exception as e:
        log.warning("[joern] CPG build error: %s", e)
        return None

    _CpgCache.set(target, cpg_path)
    return cpg_path


def register_joern_tool(reg, target_path: str) -> None:
    """Register a `cpg_slice` tool. No-op-friendly: registers even when Joern is
    absent so the model sees consistent tools; calls return a graceful message."""

    def cpg_slice(i: dict) -> str:
        # Every failure path returns the uniform _SKIP sentinel: no paths, no
        # stderr, nothing the model could mistake for a code finding.
        if not joern_available():
            return _SKIP

        sink_category = i.get("sink", "division").strip().lower()
        sink_filter = _PQC_SINK_FILTERS.get(sink_category, sink_category)
        depth = int(i.get("depth", 20))

        cpg = _build_cpg(target_path)
        if not cpg:
            return _SKIP

        # Unique per-call output dir so a slice for one sink can never read a
        # leftover file from a previous sink/run (the glob('pqc_slice*')[0]
        # stale-file bug). Cleaned up before returning.
        slice_dir = tempfile.mkdtemp(prefix="pqc_slice_")
        out_file = str(Path(slice_dir) / "slice.json")
        try:
            try:
                # Documented usage is `joern-slice data-flow [options] [cpg]` —
                # the cpg POSITIONAL must come LAST, after the options. Passing
                # it before the options left it unbound, so joern-slice fell back
                # to its default `cpg.bin` and failed ("cpg.bin does not exist"),
                # which is the error that became the FND-"Missing CPG File" false
                # finding. Verified against `joern-slice data-flow --help`.
                r = subprocess.run(
                    ["joern-slice", "data-flow",
                     "--sink-filter", sink_filter,
                     "--slice-depth", str(depth),
                     "-o", out_file,
                     cpg],
                    capture_output=True, text=True, timeout=300,
                    cwd=_joern_workdir(),
                )
                if r.returncode != 0:
                    log.debug("[joern-slice] non-zero exit: %s", r.stderr[:300])
                    return _SKIP
            except subprocess.TimeoutExpired:
                log.debug("[joern-slice] timed out")
                return _SKIP
            except Exception as e:
                log.debug("[joern-slice] error: %s", e)
                return _SKIP

            candidates = list(Path(slice_dir).glob("*"))
            if not candidates:
                return _SKIP

            try:
                data = json.loads(candidates[0].read_text())
            except Exception:
                # A non-JSON / unexpected-shape output is not analyzable code —
                # never hand the raw bytes to the model.
                log.debug("[joern-slice] unparseable output for sink '%s'", sink_category)
                return _SKIP

            # Summarise slices into compact LLM-friendly text.
            slices = data.get("slices", data) if isinstance(data, dict) else data
            if not slices:
                return _SKIP
            return _format_slices(slices, sink_category)
        finally:
            shutil.rmtree(slice_dir, ignore_errors=True)

    def _format_slices(slices, sink_category: str) -> str:
        # Verified JSON shape (joern-slice data-flow): a single DataFlowSlice
        # object {"$type","edges","nodes":[...]}, NOT {"slices":[...]}. Each node
        # carries code/lineNumber/parentFile/parentMethod (the old parser looked
        # for method/filename, which don't exist — every file label came back
        # blank). We also accept a list-of-slices in case a future mode emits one.
        out_lines = [f"# CPG data-flow slices for sink category '{sink_category}'"]
        count = 0
        for sl in (slices if isinstance(slices, list) else [slices]):
            if count >= 15:
                out_lines.append("... (more slices truncated)")
                break
            nodes = sl.get("nodes", []) if isinstance(sl, dict) else []
            if not nodes:
                continue
            out_lines.append(f"\n## Slice {count+1}")
            for n in nodes[:60]:
                code = n.get("code", "")
                line = n.get("lineNumber", n.get("line", "?"))
                fn = (n.get("parentFile") or n.get("parentMethod")
                      or n.get("method") or n.get("filename") or "")
                if code:
                    out_lines.append(f"  {fn}:{line}: {code}")
            count += 1

        return "\n".join(out_lines)[:6000]

    # Import Tool lazily to avoid circular import at module load.
    from core.tools import Tool
    reg.add(Tool(
        "cpg_slice",
        "Get a Code Property Graph data-flow slice around crypto-relevant sinks. "
        "Slices span MULTIPLE functions/files, catching bugs that single-function "
        "reads miss (e.g. a secret flowing into a non-constant-time division). "
        "Args: sink (one of: division, comparison, rng, index), depth (default 20). "
        "Use this to trace how secret data flows to dangerous operations.",
        {
            "type": "object",
            "properties": {
                "sink": {
                    "type": "string",
                    "description": "Sink category: 'division' (KyberSlash timing), "
                                   "'comparison' (FO check/verify), 'rng' (weak seed), "
                                   "'index' (secret-indexed array).",
                },
                "depth": {
                    "type": "integer",
                    "description": "Max data-flow traversal depth (default 20).",
                },
            },
        },
        cpg_slice,
        requires="",  # registered always; graceful message when joern absent
    ))
