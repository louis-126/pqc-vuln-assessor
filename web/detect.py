"""Library auto-detection for the web frontend.

Given a target source tree, guess which curated library it is by grepping each
library's curated entry-point symbols (from libraries/*.toml) against the tree
and ranking by how many resolve. Reuses the exact same entry-point data the
scanner anchors on, so a confident detection here means the scan will anchor
well too.

Pure read-only; safe to run on any path. Falls back to a directory-name hint
when no symbols resolve (e.g. a shallow checkout or an unusual layout).
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

# Make the repo root importable so we can read config (libraries/*.toml).
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import config  # noqa: E402

_RG = shutil.which("rg")

# Distinctive path/name hints per library — a light tiebreaker, never decisive
# on its own. Keyed by library name; values are substrings that commonly appear
# in that library's tree or repo name.
_NAME_HINTS = {
    "botan":        ["botan"],
    "wolfssl":      ["wolfssl", "wolfcrypt"],
    "openssl":      ["openssl"],
    "boringssl":    ["boringssl"],
    "liboqs":       ["liboqs", "oqs"],
    "bouncycastle": ["bouncycastle", "bc-java", "bcprov"],
    "circl":        ["circl"],
}


def _count_symbol(target: Path, symbol: str, globs: list[str]) -> int:
    """Count files under `target` that contain `symbol`. ripgrep if available,
    else a bounded Python fallback."""
    if _RG:
        cmd = [_RG, "-l", "--fixed-strings", symbol]
        for g in globs:
            cmd += ["-g", g]
        cmd.append(str(target))
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return len([ln for ln in r.stdout.splitlines() if ln.strip()])
        except Exception:
            return 0
    # Fallback: walk matching files, cap the work so a huge tree can't hang.
    hits, scanned = 0, 0
    exts = tuple(g.replace("*", "") for g in globs)
    for p in target.rglob("*"):
        if scanned > 4000:
            break
        if p.is_file() and p.name.endswith(exts):
            scanned += 1
            try:
                if symbol in p.read_text(encoding="utf-8", errors="ignore"):
                    hits += 1
            except Exception:
                pass
    return hits


def detect_library(target: str | Path) -> dict:
    """Rank curated libraries by how well the target matches.

    Returns:
        {
          "best": "<library or None>",
          "confidence": "high" | "medium" | "low" | "none",
          "ranking": [{"library","symbol_hits","symbols_total","name_hint","score"}...],
        }
    """
    target = Path(target)
    ranking = []
    name_blob = str(target).lower()

    for lib in config.library_names():
        spec = config.get_library(lib)
        if not spec:
            continue
        globs = spec.globs
        # Cap symbols probed so detection stays fast on many-entry-point libs.
        probe = spec.entry_points[:12]
        hits = sum(1 for sym in probe if _count_symbol(target, sym, globs) > 0)
        name_hint = any(h in name_blob for h in _NAME_HINTS.get(lib, []))
        # Score: symbol resolution dominates; a name hint adds a small nudge.
        score = hits * 10 + (5 if name_hint else 0)
        ranking.append({
            "library": lib,
            "symbol_hits": hits,
            "symbols_total": len(probe),
            "name_hint": name_hint,
            "score": score,
        })

    ranking.sort(key=lambda r: r["score"], reverse=True)
    best = ranking[0] if ranking else None

    if not best or best["score"] == 0:
        return {"best": None, "confidence": "none", "ranking": ranking}

    # Confidence from absolute symbol resolution + margin over the runner-up.
    runner = ranking[1]["score"] if len(ranking) > 1 else 0
    if best["symbol_hits"] >= 4 and best["score"] >= runner * 2:
        conf = "high"
    elif best["symbol_hits"] >= 2:
        conf = "medium"
    else:
        conf = "low"
    return {"best": best["library"], "confidence": conf, "ranking": ranking}


if __name__ == "__main__":
    import json
    tgt = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(detect_library(tgt), indent=2))
