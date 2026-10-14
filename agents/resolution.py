"""ResolutionAgent — automatically resolves 'needs-evidence' reviewer verdicts.

After the first reviewer pass, some findings are marked needs-evidence with
specific instructions like "read tls.c lines 10150-10165 to confirm aliasing".
This agent:
  1. Parses the reviewer's reason field for file:line references and keywords
  2. Runs the requested reads/searches using the tool registry
  3. Feeds the new evidence back to the reviewer for a final verdict

The loop runs at most MAX_RESOLUTION_ROUNDS to prevent infinite cycling.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from agents.base import Agent
# Reuse the reviewer's confirm-guards so the two demote paths can never drift
# (the resolution re-review must not be able to confirm what the reviewer demotes).
from agents.reviewer import (_is_call_site_only, _op_from_clause, _op_from_code)
from core import AssessmentResult, Confidence, Finding, Severity
from core.tools import build_default_registry
from prompts import REVIEWER_SYSTEM

log = logging.getLogger("pqc")

MAX_RESOLUTION_ROUNDS = 2

# Cross-operation conflict pairs (FIPS 203 encaps/decaps, FIPS 204 sign/verify).
_OP_CONFLICT = {("encap", "decap"), ("decap", "encap"),
                ("sign", "verify"), ("verify", "sign")}

# Source-file extensions across ALL supported libraries (C/C++/Go/Java/Rust) —
# resolution was previously C-only (.c/.h), so its evidence-gathering was dead
# for botan/circl/bouncycastle. Multi-char extensions come first so e.g. '.cpp'
# never matches as '.c'. Matches the alternation _read_func_def already uses.
_SRC_EXT = r"(?:cc|cpp|cxx|hpp|hh|inc|go|java|rs|c|h)"

# Patterns to extract evidence requests from reviewer reason text.
# Matches things like "read tls.c lines 10150-10165", "read dilithium.c:9700",
# "check types.h XMEMCMP", "search for ConstantCompare in wolfcrypt"
_FILE_LINE_RE = re.compile(
    r"read\s+([^\s,]+\." + _SRC_EXT + r")\s+(?:lines?\s+)?(\d+)[-–](\d+)",
    re.IGNORECASE,
)
_FILE_COLON_RE = re.compile(
    r"read\s+([^\s,]+\." + _SRC_EXT + r"):(\d+)",
    re.IGNORECASE,
)
_SEARCH_RE = re.compile(
    r"(?:search\s+for|check\s+how|check\s+if|check\s+whether|verify)\s+"
    r"['\"]?(\w[\w_]+)['\"]?\s+(?:in|is defined|maps to)",
    re.IGNORECASE,
)


class ResolutionAgent(Agent):
    required_tools = ()

    def run(self, result: AssessmentResult, context: dict) -> list[Finding]:
        reg = build_default_registry(context["target"], context.get("globs"))
        needs = [f for f in result.findings
                 if f.confidence == Confidence.SUSPECTED
                 and any("needs-evidence" in e for e in f.evidence)]
        if not needs:
            log.info("resolution: no needs-evidence findings to resolve")
            return []
        log.info("resolution: resolving %d finding(s)", len(needs))

        for round_n in range(MAX_RESOLUTION_ROUNDS):
            still_needs = [f for f in needs
                           if f.confidence == Confidence.SUSPECTED
                           and any("needs-evidence" in e for e in f.evidence)]
            if not still_needs:
                break
            log.info("resolution round %d: %d finding(s)", round_n + 1, len(still_needs))
            for f in still_needs:
                self._resolve_one(f, reg, context)

        resolved = [f for f in needs if f.confidence != Confidence.SUSPECTED
                    or not any("needs-evidence" in e for e in f.evidence)]
        log.info("resolution: resolved %d/%d finding(s)", len(resolved), len(needs))
        return needs

    def _resolve_one(self, f: Finding, reg, context: dict) -> None:
        """Gather the evidence the reviewer asked for, then re-review."""
        reason = self._get_needs_reason(f)
        if not reason:
            return

        target = Path(context.get("target", "."))
        additional: list[str] = []

        for m in _FILE_LINE_RE.finditer(reason):
            path = self._resolve_path(m.group(1), target)
            start, end = int(m.group(2)), int(m.group(3))
            out = reg.dispatch("read_file", {"path": path, "start": start, "end": end})
            additional.append(f"[read {path}:{start}-{end}]\n{out}")

        for m in _FILE_COLON_RE.finditer(reason):
            path = self._resolve_path(m.group(1), target)
            line = int(m.group(2))
            out = reg.dispatch("read_file",
                               {"path": path, "start": max(1, line - 5),
                                "end": line + 20})
            additional.append(f"[read {path}:{line}]\n{out}")

        for m in _SEARCH_RE.finditer(reason):
            pattern = m.group(1)
            out = reg.dispatch("search_code", {"pattern": pattern})
            additional.append(f"[search {pattern!r}]\n{out}")

        # Fallback: bare file:line references anywhere in the reason text.
        if not additional:
            for m in re.finditer(r'([\w/._-]+\.' + _SRC_EXT + r'):(\d+)', reason):
                path = self._resolve_path(m.group(1), target)
                line = int(m.group(2))
                out = reg.dispatch("read_file",
                                   {"path": path, "start": max(1, line - 5),
                                    "end": line + 30})
                additional.append(f"[read {path}:{line}]\n{out}")

        # Reviewer often asks for a function's BODY it couldn't see, e.g.
        # "does not include the implementation of mlkem_cmp". Find that
        # function's DEFINITION and read it so the second-pass review can decide.
        funcs = set()
        for _m in re.finditer(
                r"(?:implementation|source(?:\s+code)?|body|definition)\s+of\s+"
                r"[`'\"]?([A-Za-z_]\w+)", reason, re.IGNORECASE):
            funcs.add(_m.group(1))
        for _m in re.finditer(r"[`'\"]?([A-Za-z_]\w+)[`'\"]?\s+function",
                              reason, re.IGNORECASE):
            funcs.add(_m.group(1))
        for _fn in [x for x in funcs if "_" in x][:3]:
            _body = self._read_func_def(_fn, reg)
            if _body:
                additional.append(f"[definition of {_fn}]\n{_body}")

        # Call-site-only demotion: the reviewer demoted this because the model
        # cited where a function is CALLED, not the vulnerable line inside it.
        # Follow the call into the callee's body so the re-review can see the real
        # implementation (the risky-line slices already flag the offending line
        # there). This is the recurring "proving_line_is_call_site_only" loss.
        if "call_site" in reason.lower() and f.file and f.line:
            cpath = self._resolve_path(f.file, target)
            ln = int(f.line)
            window = reg.dispatch("read_file",
                                  {"path": cpath, "start": max(1, ln - 5), "end": ln + 90})
            if window and window.strip():
                additional.append(f"[implementation around {cpath}:{ln}]\n{window}")
            cited = reg.dispatch("read_file", {"path": cpath, "start": ln, "end": ln})
            for _cm in re.finditer(r"\b([A-Za-z_]\w{2,})\s*\(", cited or ""):
                _fn = _cm.group(1)
                if _fn in ("if", "while", "for", "return", "sizeof", "switch", "do"):
                    continue
                _cbody = self._read_func_def(_fn, reg)
                if _cbody:
                    additional.append(
                        f"[definition of {_fn} (callee at the cited call site)]\n{_cbody}")
                    break

        if not additional:
            log.debug("resolution: could not extract evidence requests from: %s",
                      reason[:200])
            return

        # Add the additional evidence to the finding.
        for ev in additional:
            f.add_evidence("resolution", ev)

        # Re-run the reviewer on just this one finding with the new evidence.
        self._re_review(f, additional)

    def _re_review(self, f: Finding, additional: list[str]) -> None:
        """Give the reviewer the additional evidence and update the finding."""
        add_text = "\n\n".join(additional)
        user = (
            f"Second-pass review. You previously returned needs-evidence for "
            f"this finding. Here is the additional evidence you requested.\n\n"
            f"### FINDING {f.id}\n"
            f"title: {f.title}\nclaimed_severity: {f.severity.name}\n"
            f"location: {f.file}:{f.line}\ncwe: {f.cwe}\n"
            f"description: {f.description}\n\n"
            f"ORIGINAL EVIDENCE:\n"
            f"{chr(10).join(f.evidence[:-len(additional)])}\n\n"
            f"ADDITIONAL EVIDENCE (what you requested):\n{add_text}\n\n"
            f"Give a final verdict. Return JSON: "
            f'[{{"id": "{f.id}", "verdict": "confirmed|disputed|needs-evidence", '
            f'"severity": "...", "reason": "...", "corrected_fix": "..."}}]'
        )
        try:
            data = self.llm.complete_json(REVIEWER_SYSTEM, user, max_tokens=2048)
        except Exception as e:
            log.warning("resolution re-review failed for %s: %s", f.id, e)
            return

        verdicts = data if isinstance(data, list) else data.get("verdicts", [])
        for v in verdicts:
            if not isinstance(v, dict):
                continue
            verdict = str(v.get("verdict", "needs-evidence")).lower()
            log.info("resolution: %s -> %s (was needs-evidence)", f.id, verdict)

            _VERDICT_CONF = {
                "confirmed": Confidence.CONFIRMED,
                "disputed": Confidence.SUSPECTED,
                "needs-evidence": Confidence.SUSPECTED,
            }
            if verdict == "confirmed":
                spec_clause         = str(v.get("spec_clause", "")).strip()
                proving_line        = str(v.get("proving_line", "")).strip()
                claim_justification = str(v.get("claim_justification", "")).strip()
                missing = []
                if not spec_clause:
                    missing.append("spec_clause")
                if not proving_line:
                    missing.append("proving_line")
                if not claim_justification:
                    missing.append("claim_justification")
                # Parity with the main reviewer (request #1): a re-review must
                # not be able to confirm what the reviewer would demote. Reuse
                # the SAME guards (imported, not duplicated) so the two demote
                # paths never drift.
                if proving_line and _is_call_site_only(proving_line):
                    missing.append("proving_line_is_call_site_only")
                clause_op = _op_from_clause(spec_clause)
                code_op = _op_from_code(f.entry_point, f.file, proving_line, f.title)
                if clause_op and code_op and (clause_op, code_op) in _OP_CONFLICT:
                    missing.append(
                        f"spec_clause/operation_mismatch "
                        f"(clause={clause_op}, code={code_op})")
                if missing:
                    log.info(
                        "resolution: demoted '%s' confirmed→needs-evidence "
                        "(missing/invalid: %s)", f.id, ", ".join(missing)
                    )
                    verdict = "needs-evidence"
                    v["reason"] = (
                        f"[auto-demoted: missing {', '.join(missing)}] "
                        + v.get("reason", "")
                    )
                else:
                    f.add_evidence("spec_clause", spec_clause)
                    f.add_evidence("proving_line", proving_line)
                    f.add_evidence("claim_justification", claim_justification)
                    if not f.spec_reference:
                        f.spec_reference = spec_clause
            f.confidence = _VERDICT_CONF.get(verdict, Confidence.SUSPECTED)
            try:
                f.severity = Severity.from_str(v.get("severity", f.severity.name))
            except (KeyError, ValueError):
                pass
            if verdict == "disputed":
                if not f.title.startswith("[DISPUTED]"):
                    f.title = f"[DISPUTED] {f.title}"
                f.severity = Severity(max(0, int(f.severity) - 1))
            if verdict == "confirmed":
                from core.findings import cvss31_base, default_cvss_vector
                vec = str(v.get("cvss_vector", "")).strip()
                if vec and cvss31_base(vec) > 0:
                    f.cvss_vector = vec
                elif not f.cvss_vector:
                    f.cvss_vector = default_cvss_vector(f.severity, f.cwe)
                    f.add_evidence("cvss", "vector derived from severity/CWE "
                                   "(reviewer vector missing or unparseable)")
            f.add_evidence("resolution_verdict",
                           f"verdict={verdict}: {v.get('reason', '')}")
            if v.get("corrected_fix"):
                f.add_evidence("resolution_fix", str(v["corrected_fix"]))

    def _read_func_def(self, fn: str, reg) -> str:
        """Locate a function's DEFINITION (impl .c signature line) and read its
        body. Prefers a .c under src/ whose line looks like the definition (name
        '(' with no '=' before and no ';'), skipping test/doc matches."""
        loc = reg.dispatch("search_code", {"pattern": fn})
        best = None
        for ln in loc.splitlines():
            mm = re.match(r"([^\s:]+\.(?:c|cc|cpp|cxx|go|java|rs)):(\d+):(.*)", ln)
            if not mm:
                continue
            fp, n, content = mm.group(1), int(mm.group(2)), mm.group(3)
            if any(x in fp.lower() for x in
                   ("/test", "test_", "_test.", "/doc/", "/dox", "/example")):
                continue
            fpl = fp.lower()
            score = 2 if any(seg in fpl for seg in
                             ("src/", "/lib/", "internal/", "crypto/")) else 0
            if (re.search(re.escape(fn) + r"\s*\(", content)
                    and "=" not in content.split(fn)[0] and ";" not in content):
                score += 3
            if best is None or score > best[0]:
                best = (score, fp, n)
        if best is None:
            return ""
        _, fp, n = best
        # Initial read: standard 60-line window around the definition.
        body = reg.dispatch("read_file",
                            {"path": fp, "start": max(1, n - 3), "end": n + 60})
        # If the body is heavy with #ifdef (platform dispatch functions like
        # wc_GenerateSeed), expand to 200 lines so the reviewer sees at least
        # one complete platform branch rather than just the ifdef ladder.
        ifdef_count = body.count("#ifdef") + body.count("#if ")
        if ifdef_count >= 3:
            body = reg.dispatch("read_file",
                                {"path": fp, "start": max(1, n - 3), "end": n + 200})
        return body

    def _resolve_path(self, mentioned: str, target: Path) -> str:
        """Given a filename or partial path from reviewer text, return the
        best relative path within the target tree.

        The reviewer often writes bare names like 'tls.c' or 'dilithium.c'
        when the actual path is 'src/tls.c' or 'wolfcrypt/src/dilithium.c'.
        We search the tree for the filename and return the first match.
        If the path already works as-is (e.g. 'src/tls.c'), return it directly.
        """
        # If it already contains a slash it might already be correct — try it.
        candidate = target / mentioned
        if candidate.exists():
            return mentioned

        # Try stripping any leading directory components and searching.
        fname = Path(mentioned).name
        matches = list(target.rglob(fname))
        if matches:
            # Prefer the shortest path (least deeply nested).
            best = min(matches, key=lambda p: len(p.parts))
            try:
                return str(best.relative_to(target))
            except ValueError:
                pass

        # Return as-is and let the registry handle the error gracefully.
        return mentioned

    def _get_needs_reason(self, f: Finding) -> str:
        """Extract the reviewer's needs-evidence reason from the finding evidence."""
        for e in f.evidence:
            if "needs-evidence" in e and "verdict=" in e:
                # Strip the "verdict=needs-evidence: " prefix
                return re.sub(r"^\[.*?\]\s*verdict=needs-evidence:\s*", "", e,
                              flags=re.DOTALL).strip()
        # Fallback: return all review evidence combined
        return " ".join(e for e in f.evidence if "[review]" in e or "resolution" in e)
