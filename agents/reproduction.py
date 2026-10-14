"""ReproductionAgent — minimized repro + dual-tool confirmation + impact triage.

This is the agent the handover called `ExploitAgent`, scoped deliberately to
what a responsible-disclosure submission actually needs:

  WHAT IT DOES
    * Minimize a crashing input to the smallest reliable reproducer.
    * Confirm with TWO independent tools — ASan and Valgrind on the same PoC
      (design decision #4: one tool alone is insufficient evidence).
    * Triage IMPACT for CVSS: classify the memory error (read vs. write,
      use-after-free vs. overflow), note whether the faulting offset/size looks
      attacker-influenced, and assign a severity band. This is *characterisation*
      for the report, not exploitation.
    * Save the reproducer + logs to disk for the researcher and the vendor.

  WHAT IT DOES NOT DO  (intentional, do not "fix" this)
    * It does not develop a working exploit: no heap grooming/feng-shui, no
      ROP/JOP chain construction, no ASLR/DEP bypass, no payload/shellcode, no
      control-flow hijack PoC. A vendor needs a reliable crash and an impact
      assessment to triage and patch; weaponisation is left to a human and is
      out of scope for automated generation regardless of disclosure intent.

  The "RCE-potential vs crash-only" question (open problem #5) is answered here
  only at the level of *classification* (does the bug yield a controllable write
  primitive?), which informs CVSS — not by building the primitive.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from agents.base import Agent
from core import AssessmentResult, Confidence, Finding, Phase, Severity

log = logging.getLogger("pqc")

# Impact classification from sanitizer text -> (label, exploitability_note, band).
_IMPACT_RULES = [
    (re.compile(r"heap-use-after-free.*WRITE", re.I | re.S),
     "UAF write", "Controllable write primitive possible; high impact band.", Severity.CRITICAL),
    (re.compile(r"heap-use-after-free", re.I),
     "UAF (read)", "Use-after-free; impact depends on reuse — review object lifecycle.", Severity.HIGH),
    (re.compile(r"WRITE of size", re.I),
     "OOB write", "Out-of-bounds write; assess offset controllability.", Severity.CRITICAL),
    (re.compile(r"READ of size", re.I),
     "OOB read", "Out-of-bounds read; potential info-leak.", Severity.HIGH),
    (re.compile(r"double-free", re.I),
     "double free", "Allocator corruption; review free paths.", Severity.HIGH),
]


class ReproductionAgent(Agent):
    required_tools = ("valgrind",)  # ASan comes from the already-built harness

    def run(self, result: AssessmentResult, context: dict) -> list[Finding]:
        # Operate on confirmed crash findings from fuzzing (or asymmetric
        # crashes from differential).
        crash_findings = [
            f for f in result.findings
            if f.phase in (Phase.FUZZING, Phase.DIFFERENTIAL) and f.artifacts
        ]
        if not crash_findings:
            log.info("reproduction: no crash findings with artifacts; skipping")
            return []

        produced: list[Finding] = []
        for cf in crash_findings:
            crash_input = Path(cf.artifacts[0])
            if not crash_input.exists():
                continue
            repro = self._minimize(cf, crash_input, context)
            asan = self._confirm_asan(cf, repro, context)
            valgrind = self._confirm_valgrind(cf, repro, context)
            produced.append(self._record(result, cf, repro, asan, valgrind))
        return produced

    # ---- stages --------------------------------------------------------

    def _minimize(self, cf: Finding, crash_input: Path, context: dict) -> Path:
        """Shrink the crashing input. Uses the libFuzzer binary's own -minimize
        if available; otherwise keeps the original. The reproducer is what the
        vendor receives, so it is saved verbatim to disk."""
        binary = self.workdir / f"harness_{cf.entry_point}"
        out = self.workdir / f"repro_{cf.id}.bin"
        if binary.exists():
            res = self.sh(
                [str(binary), "-minimize_crash=1", "-runs=20000",
                 f"-exact_artifact_path={out}", str(crash_input)],
                timeout=300,
            )
            self.save_artifact(f"minimize_{cf.id}.log", res.stdout + res.stderr)
        if not out.exists():
            out.write_bytes(crash_input.read_bytes())
        return out

    def _confirm_asan(self, cf: Finding, repro: Path, context: dict) -> str:
        binary = self.workdir / f"harness_{cf.entry_point}"
        if not binary.exists():
            return ""
        res = self.sh([str(binary), str(repro)], timeout=60)
        log_text = res.stderr or res.stdout
        self.save_artifact(f"asan_{cf.id}.log", log_text)
        return log_text

    def _confirm_valgrind(self, cf: Finding, repro: Path, context: dict) -> str:
        """Second, independent tool on the SAME reproducer (design decision #4).

        Valgrind needs a non-ASan build; researchers supply it via
        context['valgrind_binary']. Without it we record that the second
        confirmation is pending rather than claiming dual confirmation."""
        vbin = context.get("valgrind_binary")
        if not vbin or not Path(vbin).exists():
            log.info("reproduction: no non-ASan binary for Valgrind; "
                     "second-tool confirmation pending for %s", cf.id)
            return ""
        res = self.sh(
            ["valgrind", "--error-exitcode=99", "--leak-check=full",
             str(vbin), str(repro)],
            timeout=300,
        )
        log_text = res.stderr
        self.save_artifact(f"valgrind_{cf.id}.log", log_text)
        return log_text

    def _classify_impact(self, sanitizer_text: str):
        for pat, label, note, band in _IMPACT_RULES:
            if pat.search(sanitizer_text):
                return label, note, band
        return "unclassified", "Could not classify from sanitizer output.", Severity.MEDIUM

    def _record(self, result: AssessmentResult, cf: Finding, repro: Path,
                asan: str, valgrind: str) -> Finding:
        label, note, band = self._classify_impact(asan or valgrind)

        # Dual confirmation: both tools must independently report a memory error.
        asan_hit = bool(re.search(r"ERROR: AddressSanitizer", asan))
        valgrind_hit = bool(re.search(r"Invalid (read|write|free)|definitely lost", valgrind))
        if asan_hit and valgrind_hit:
            confidence = Confidence.CONFIRMED
            conf_note = "Confirmed by ASan AND Valgrind on the same reproducer."
        elif asan_hit or valgrind_hit:
            confidence = Confidence.LIKELY
            conf_note = ("Confirmed by one tool; second-tool confirmation "
                         "pending (supply a non-ASan binary via 'valgrind_binary').")
        else:
            confidence = Confidence.SUSPECTED
            conf_note = "Reproducer saved but neither tool reproduced cleanly; review manually."

        f = Finding(
            title=f"Reproduced: {label} in {cf.entry_point}",
            phase=Phase.REPRODUCTION,
            severity=max(band, cf.severity),
            confidence=confidence,
            description=(
                f"Minimized reproducer for finding {cf.id}. Impact class: {label}. "
                f"{note} {conf_note}\n\n"
                f"Scope note: this is a crash reproducer + impact characterisation "
                f"for disclosure/CVSS. It is not a weaponised exploit."
            ),
            entry_point=cf.entry_point,
            cwe=cf.cwe,
            cvss_vector=cf.cvss_vector,
            matched_target=cf.matched_target,  # carry CVE-2026-5460 mapping through
            artifacts=[str(repro),
                       str(self.workdir / f"asan_{cf.id}.log"),
                       str(self.workdir / f"valgrind_{cf.id}.log")],
        )
        if asan:
            f.add_evidence("asan", asan)
        if valgrind:
            f.add_evidence("valgrind", valgrind)
        return result.add(f)
