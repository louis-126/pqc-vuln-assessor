"""StaticAnalysisAgent.

Pipeline:
  1. Run flawfinder, cppcheck, semgrep (whichever are installed) over the tree.
  2. Run targeted grep heuristics for crypto-specific anti-patterns
     (weak RNG seeds, incomplete key validation, etc.).
  3. Pre-filter every tool's output (cap + drop noise).
  4. Hand the cleaned output + relevant source to the LLM for triage and for
     spec comparison against FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA).

Rediscovery targets handled here: WF-001 (weak srand seed) and WF-004
(mlkem_check_public missing NTT validity). Both are detectable statically.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from agents.base import Agent
from core import (
    AssessmentResult, Confidence, Finding, Phase, Severity, prefilter,
)
from specs.fips_refs import spec_excerpt

log = logging.getLogger("pqc")

# Targeted source greps. Each maps a regex to a candidate finding sketch the
# LLM then confirms or rejects. Keeping these explicit makes the heuristic
# layer auditable (and reproducible across runs).
GREP_HEURISTICS = [
    {
        "id": "weak-rng-seed",
        "pattern": re.compile(r"srand\s*\(\s*time\s*\(\s*NULL\s*\)\s*\)"),
        "title": "Predictable RNG seed (srand(time(NULL)))",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-337",
        "cvss": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "maps_to": "WF-001",
        "note": "time(NULL) gives ~86400 seeds/day; key material becomes brute-forceable.",
    },
    {
        "id": "mlkem-pubkey-check",
        "pattern": re.compile(r"mlkem_check_public|MLKEM_Q"),
        "title": "Possibly incomplete ML-KEM public-key validation",
        "severity": Severity.HIGH,
        "cwe": "CWE-20",
        "cvss": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
        "maps_to": "WF-004",
        "note": "Range check on coefficients alone does not establish NTT validity (FIPS 203 §7.2).",
        "spec": "FIPS 203 §7.2",
    },
    {
        "id": "memcpy-unchecked-len",
        "pattern": re.compile(r"memcpy\s*\([^,]+,[^,]+,\s*\w+_len\s*\)"),
        "title": "memcpy with caller-supplied length (review bounds)",
        "severity": Severity.MEDIUM,
        "cwe": "CWE-120",
        "cvss": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "maps_to": None,
    },
]

SPEC_REVIEW_SYSTEM = """\
You are a cryptographic implementation auditor. You compare C source against \
the relevant NIST FIPS specification and report ONLY concrete deviations that \
have security impact. Do not speculate. For ML-KEM use FIPS 203; for ML-DSA \
use FIPS 204.

For each deviation return an object with keys: title, severity \
(INFO|LOW|MEDIUM|HIGH|CRITICAL), cwe, spec_reference (e.g. 'FIPS 203 §7.2'), \
description (what the code does vs. what the spec requires), and confidence \
(confirmed|likely|suspected). Return a JSON object: {"findings": [...]}. \
Empty list if the code conforms."""


class StaticAnalysisAgent(Agent):
    required_tools = ("flawfinder", "cppcheck", "semgrep", "grep")

    def run(self, result: AssessmentResult, context: dict) -> list[Finding]:
        target = Path(result.target)
        missing = self.missing_tools()
        if missing:
            log.info("static: missing tools (degrading): %s", ", ".join(missing))

        new: list[Finding] = []
        tool_outputs: dict[str, str] = {}

        # 1. General-purpose scanners ------------------------------------
        if self._has("flawfinder"):
            out = self.sh(["flawfinder", "--quiet", "--dataonly", str(target)])
            tool_outputs["flawfinder"] = prefilter("flawfinder", out.stdout)
        if self._has("cppcheck"):
            out = self.sh(["cppcheck", "--enable=warning,portability",
                           "--quiet", "--template=gcc", str(target)])
            tool_outputs["cppcheck"] = prefilter("cppcheck", out.stderr or out.stdout)
        if self._has("semgrep"):
            out = self.sh(["semgrep", "--config=auto", "--quiet",
                           "--no-git-ignore", str(target)])
            tool_outputs["semgrep"] = prefilter("semgrep", out.stdout)

        # 2. Targeted crypto heuristics ----------------------------------
        new += self._run_grep_heuristics(target, result)

        # 3. LLM triage of scanner output --------------------------------
        if any(tool_outputs.values()):
            new += self._llm_triage(tool_outputs, result)

        # 4. Spec comparison on the entry-point source files -------------
        new += self._spec_review(target, context.get("entry_points", []), result)

        return new

    # ---- stage implementations -----------------------------------------

    def _has(self, tool: str) -> bool:
        return self.available_tools().get(tool, False)

    def _run_grep_heuristics(self, target: Path, result: AssessmentResult) -> list[Finding]:
        found: list[Finding] = []
        sources = list(target.rglob("*.c")) + list(target.rglob("*.h"))
        for src in sources:
            try:
                text = src.read_text(errors="ignore")
            except OSError:
                continue
            for h in GREP_HEURISTICS:
                for m in h["pattern"].finditer(text):
                    line_no = text.count("\n", 0, m.start()) + 1
                    # Confirm with the LLM before promoting to a finding, so a
                    # bare pattern match (e.g. MLKEM_Q used correctly) is not
                    # reported blindly.
                    confirmed = self._confirm_heuristic(h, src, text, line_no)
                    if not confirmed:
                        continue
                    f = Finding(
                        title=h["title"],
                        phase=Phase.STATIC,
                        severity=h["severity"],
                        confidence=Confidence.LIKELY,
                        description=confirmed,
                        file=str(src.relative_to(target)),
                        line=line_no,
                        cwe=h.get("cwe"),
                        cvss_vector=h.get("cvss"),
                        spec_reference=h.get("spec"),
                        matched_target=h.get("maps_to"),
                    )
                    f.add_evidence("grep", h["note"])
                    found.append(result.add(f))
                    break  # one finding per heuristic per file is enough
        return found

    def _confirm_heuristic(self, h: dict, src: Path, text: str, line: int) -> str | None:
        """Ask the LLM whether the matched line is a real instance of the
        anti-pattern. Returns a confirmed description or None."""
        lines = text.splitlines()
        ctx = "\n".join(lines[max(0, line - 8): line + 8])
        spec = spec_excerpt(h["spec"]) if h.get("spec") else ""
        system = (
            "You confirm or reject a suspected crypto implementation flaw. "
            "Reply JSON {\"is_flaw\": bool, \"reason\": str}. Be strict: only "
            "confirm if the security impact in the handover note actually holds "
            "for this code."
        )
        user = (
            f"Suspected: {h['title']}\nNote: {h['note']}\n"
            f"{('Spec: ' + spec) if spec else ''}\n"
            f"File: {src.name}:{line}\n\nContext:\n```c\n{ctx}\n```"
        )
        try:
            resp = self.llm.complete_json(system, user, max_tokens=512)
            if isinstance(resp, dict) and resp.get("is_flaw"):
                return resp.get("reason", h["note"])
        except Exception as e:
            log.warning("heuristic confirm failed (%s): %s", h["id"], e)
            # On LLM failure, keep the raw heuristic note rather than dropping it.
            return h["note"]
        return None

    def _llm_triage(self, tool_outputs: dict[str, str], result: AssessmentResult) -> list[Finding]:
        system = (
            "You triage static-analysis output for a PQC crypto library. "
            "Discard false positives and test-only noise. Report only security-"
            "relevant defects. Return JSON {\"findings\": [{title, severity, cwe, "
            "file, line, description, confidence}]}."
        )
        blob = "\n\n".join(f"### {tool}\n{out}" for tool, out in tool_outputs.items() if out)
        try:
            resp = self.llm.complete_json(system, blob, max_tokens=3072)
        except Exception as e:
            log.warning("static triage failed: %s", e)
            return []
        return self._materialise(resp, result, default_sev=Severity.MEDIUM,
                                 evidence_src="static-triage")

    def _spec_review(self, target: Path, entry_points: list[str],
                     result: AssessmentResult) -> list[Finding]:
        """Locate files implementing the entry points and compare to spec."""
        found: list[Finding] = []
        sources = list(target.rglob("*.c"))
        for src in sources:
            try:
                text = src.read_text(errors="ignore")
            except OSError:
                continue
            if not any(ep in text for ep in entry_points):
                continue
            which_spec = "FIPS 204" if ("dilithium" in src.name or "mldsa" in src.name) else "FIPS 203"
            user = (
                f"Specification context:\n{spec_excerpt(which_spec)}\n\n"
                f"Source file {src.name} (excerpt):\n```c\n{text[:6000]}\n```"
            )
            try:
                resp = self.llm.complete_json(SPEC_REVIEW_SYSTEM, user, max_tokens=2048)
            except Exception as e:
                log.warning("spec review failed for %s: %s", src.name, e)
                continue
            for f in self._materialise(resp, result, default_sev=Severity.MEDIUM,
                                       evidence_src=f"spec-review/{src.name}",
                                       file_default=str(src.relative_to(target))):
                # Map an ML-KEM pubkey-validation deviation to WF-004 if not
                # already mapped by the grep layer.
                if f.matched_target is None and "check_public" in (f.description or "") \
                        and "NTT" in (f.description or ""):
                    f.matched_target = "WF-004"
                found.append(f)
        return found

    def _materialise(self, resp, result: AssessmentResult, default_sev: Severity,
                     evidence_src: str, file_default: str | None = None) -> list[Finding]:
        items = resp.get("findings", []) if isinstance(resp, dict) else []
        out: list[Finding] = []
        for it in items:
            if not isinstance(it, dict) or not it.get("title"):
                continue
            try:
                sev = Severity.from_str(it.get("severity", default_sev.name))
            except (KeyError, ValueError):
                sev = default_sev
            try:
                conf = Confidence(it.get("confidence", "suspected"))
            except ValueError:
                conf = Confidence.SUSPECTED
            f = Finding(
                title=it["title"],
                phase=Phase.STATIC,
                severity=sev,
                confidence=conf,
                description=it.get("description", ""),
                file=it.get("file") or file_default,
                line=it.get("line"),
                cwe=it.get("cwe"),
                spec_reference=it.get("spec_reference"),
            )
            f.add_evidence(evidence_src, it.get("description", ""))
            out.append(result.add(f))
        return out
