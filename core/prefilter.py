"""Pre-filter raw tool output before it reaches an LLM.

Design decision #2 from the handover: cap per-tool output (~4000 chars) and
strip obvious false positives first. The point is twofold — keep token cost
down, and stop the model wasting reasoning budget on noise it would have to
discard anyway.

These filters are deliberately conservative: we only drop lines that are
*definitely* irrelevant, because a dropped real finding is far worse than a
surviving false positive (the LLM can still discard those).
"""
from __future__ import annotations

import re

DEFAULT_CAP = 4000

# Lines matching these are noise from the named tool. Keep this list tight and
# documented — every entry should have a clear reason.
_FALSE_POSITIVE_PATTERNS: dict[str, list[re.Pattern]] = {
    "flawfinder": [
        re.compile(r"Examining "),                         # progress chatter
        re.compile(r"^Hits = \d"),                          # summary header
        re.compile(r"^(Lines|Physical|Time) "),             # stats footer
        re.compile(r"\[0\]"),                               # risk-level 0 hits
        re.compile(r"No hits found"),
    ],
    "cppcheck": [
        re.compile(r"\(information\)"),                     # not a defect class
        re.compile(r"missingIncludeSystem"),               # build-config noise
        re.compile(r"checkersReport"),
        re.compile(r"^Checking "),
    ],
    "semgrep": [
        re.compile(r"^\s*$"),
        re.compile(r"ran \d+ rules"),
        re.compile(r"Scanning \d+ files"),
    ],
    "grep": [
        re.compile(r"^Binary file .* matches$"),
    ],
}

# Cross-tool: lines that are almost always irrelevant for crypto review.
_GLOBAL_DROP = [
    re.compile(r"^\s*//"),            # bare comment-only lines from grep context
    re.compile(r"test[s]?/.*\bprintf\b"),  # printf in test files
]


def prefilter(tool: str, raw: str, cap: int = DEFAULT_CAP,
              keep_context: bool = True) -> str:
    """Return a cleaned, length-capped version of `raw` for tool `tool`.

    `keep_context=False` collapses blank lines aggressively (use for very
    chatty tools); True preserves single blank-line separation for readability.
    """
    if not raw:
        return ""
    patterns = _FALSE_POSITIVE_PATTERNS.get(tool, []) + _GLOBAL_DROP
    kept: list[str] = []
    for line in raw.splitlines():
        if any(p.search(line) for p in patterns):
            continue
        if not keep_context and not line.strip():
            continue
        kept.append(line)

    cleaned = "\n".join(kept).strip()
    if len(cleaned) <= cap:
        return cleaned
    # Truncate at a line boundary near the cap so we never cut mid-finding.
    head = cleaned[:cap]
    nl = head.rfind("\n")
    if nl > cap * 0.6:
        head = head[:nl]
    dropped = len(cleaned) - len(head)
    return head + f"\n...[prefilter truncated {dropped} chars / {tool}]"


def chunk_for_review(text: str, cap: int = DEFAULT_CAP) -> list[str]:
    """Split long source/text into <=cap chunks on line boundaries, for when a
    single file genuinely needs full LLM review (e.g. spec comparison)."""
    out, cur, size = [], [], 0
    for line in text.splitlines(keepends=True):
        if size + len(line) > cap and cur:
            out.append("".join(cur))
            cur, size = [], 0
        cur.append(line)
        size += len(line)
    if cur:
        out.append("".join(cur))
    return out
