"""core/finding_similarity.py — semantic near-duplicate detection for findings.

The cross-pass union in `ResearcherAgent._extract_call` dedups on an EXACT key
(basename, line, cwe). That misses the common case where two passes surface the
SAME underlying bug with a slightly different line, a sibling CWE, or different
wording — so the report double-counts it. This adds a lightweight,
dependency-free "are these the same bug?" check to run AFTER the exact-key miss.

Design (deliberately conservative — never merge two genuinely different bugs):
  - file compared by basename (a different file is always a different bug)
  - CWE normalised to a coarse DEFECT CLASS (e.g. CWE-203 and CWE-208 are both
    observable-timing -> "sidechannel"), so sibling CWEs for one bug match
  - line proximity within a small window
  - title+description compared by Jaccard word-set overlap

Adapted from VulnClaw's finding_similarity.py (MIT) for the PQC source-audit
domain: no URL/web-vuln logic; CWE-class aliases instead of web-vuln aliases.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.findings import Finding

_WORD = re.compile(r"[a-z0-9_]+")

# Bare CWE numbers grouped into the SAME underlying PQC defect class. Two findings
# whose CWEs land in the same class are treated as the same KIND of bug (the LLM
# often labels one non-constant-time compare CWE-203 and another CWE-208).
_CWE_CLASS = {
    # observable timing / side-channel / info leak
    "200": "sidechannel", "203": "sidechannel", "208": "sidechannel",
    "310": "sidechannel", "327": "sidechannel", "385": "sidechannel",
    # weak / predictable randomness
    "330": "weakrng", "335": "weakrng", "338": "weakrng",
    # memory safety
    "120": "memory", "125": "memory", "190": "memory", "415": "memory",
    "416": "memory", "476": "memory", "787": "memory",
    # input / key / signature validation
    "20": "validation", "345": "validation", "347": "validation",
    "680": "validation",
}

# Tunables — conservative so we never merge two genuinely distinct bugs.
_LINE_WINDOW = 12          # lines apart that still counts as "same location"
_TEXT_THRESHOLD = 0.50     # title+desc Jaccard to call two findings one bug
_TEXT_THRESHOLD_NOFILE = 0.65   # stricter when neither finding has a file


def _basename(path: str | None) -> str:
    if not path:
        return ""
    return re.split(r"[\\/]", path.strip())[-1].lower()


def _cwe_class(cwe: str | None) -> str:
    """Bare CWE number mapped to a coarse defect class; the bare number if the
    class is unknown; '' if there is no CWE at all."""
    if not cwe:
        return ""
    m = re.search(r"\d+", cwe)
    if not m:
        return ""
    return _CWE_CLASS.get(m.group(0), m.group(0))


def _words(text: str) -> set[str]:
    return set(_WORD.findall((text or "").lower()))


def jaccard(a: str, b: str) -> float:
    """Word-set Jaccard similarity of two strings, in [0, 1]."""
    wa, wb = _words(a), _words(b)
    if not wa or not wb:
        return 0.0
    return len(wa & wb) / len(wa | wb)


def _text(f: "Finding") -> str:
    return f"{f.title} {f.description}"


def same_bug(f1: "Finding", f2: "Finding") -> bool:
    """True if f1 and f2 are very likely the SAME underlying bug.

    Same file is required (basename match). Then EITHER the locations are close
    and the CWE classes agree, OR the wording overlaps strongly and the CWE
    classes are compatible (equal, or at least one unknown). With no file on
    either finding, fall back to a stricter pure-text comparison.
    """
    b1, b2 = _basename(f1.file), _basename(f2.file)
    if b1 and b2 and b1 != b2:
        return False
    if not b1 and not b2:
        return jaccard(_text(f1), _text(f2)) >= _TEXT_THRESHOLD_NOFILE

    c1, c2 = _cwe_class(f1.cwe), _cwe_class(f2.cwe)
    cwe_compatible = (not c1) or (not c2) or (c1 == c2)

    # Location-based: same spot, same defect class.
    if f1.line is not None and f2.line is not None and c1 and c2 and c1 == c2:
        if abs(int(f1.line) - int(f2.line)) <= _LINE_WINDOW:
            return True

    # Text-based: same file, strongly overlapping wording, compatible class.
    if cwe_compatible and jaccard(_text(f1), _text(f2)) >= _TEXT_THRESHOLD:
        return True

    return False
