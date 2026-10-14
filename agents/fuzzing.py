"""FuzzingAgent — generate AFL++ harnesses per entry point, build with ASan,
fuzz, and triage crashes.

Flow per entry point:
  1. LLM drafts a libFuzzer/AFL-style harness that feeds fuzz input into the
     target API (decode -> operate), based on the function signature.
  2. Build with clang + -fsanitize=address,undefined.
  3. Run afl-fuzz (or the libFuzzer binary) for a bounded budget.
  4. Collect crashing inputs; triage each (sanitizer class, faulting frame).

Crash findings escalate to the reproduction agent. The TLS hybrid key-share
path is where the known heap-UAF (CVE-2026-5460) surfaces.

Note on scope: harnesses *exercise* the API to find crashes; they are test
drivers, not exploits. Turning a crash into a working exploit is explicitly out
of scope (see reproduction.py).
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from agents.base import Agent
from core import AssessmentResult, Confidence, Finding, Phase, Severity, prefilter

log = logging.getLogger("pqc")

HARNESS_SYSTEM = """\
You write libFuzzer-style C harnesses (LLVMFuzzerTestOneInput) for a crypto
library API. The harness must: include the right headers, initialise minimal
state, map the fuzz buffer to the function's inputs (decoding where needed),
call the target, and free all resources to avoid false-positive leaks. Keep it
compilable and minimal. Return JSON {"harness_c": "<code>", "build_notes": "<str>"}.
This is a test driver for crash discovery only."""

# Sanitizer output -> (severity, cwe). Heap UAF and OOB-write are the high ones.
_SANITIZER_CLASS = [
    (re.compile(r"heap-use-after-free", re.I), Severity.CRITICAL, "CWE-416"),
    (re.compile(r"heap-buffer-overflow.*WRITE|WRITE.*heap-buffer", re.I), Severity.CRITICAL, "CWE-787"),
    (re.compile(r"heap-buffer-overflow", re.I), Severity.HIGH, "CWE-125"),
    (re.compile(r"stack-buffer-overflow", re.I), Severity.HIGH, "CWE-121"),
    (re.compile(r"global-buffer-overflow", re.I), Severity.HIGH, "CWE-787"),
    (re.compile(r"double-free", re.I), Severity.CRITICAL, "CWE-415"),
    (re.compile(r"SEGV|null pointer", re.I), Severity.MEDIUM, "CWE-476"),
    (re.compile(r"runtime error:.*overflow", re.I), Severity.MEDIUM, "CWE-190"),
]


class FuzzingAgent(Agent):
    required_tools = ("clang", "afl-fuzz")

    def __init__(self, llm, workdir, run_seconds: int = 120):
        super().__init__(llm, workdir)
        self.run_seconds = run_seconds

    def run(self, result: AssessmentResult, context: dict) -> list[Finding]:
        entry_points = context.get("entry_points", [])
        if not entry_points:
            log.info("fuzzing: no entry points provided; skipping")
            return []

        new: list[Finding] = []
        for ep in entry_points:
            harness_path = self._generate_harness(ep, context)
            if harness_path is None:
                continue
            binary = self._build(harness_path, context)
            if binary is None:
                log.info("fuzzing: build failed for %s; harness saved for manual use", ep)
                continue
            crashes = self._fuzz(binary, ep)
            for crash in crashes:
                new.append(self._triage_crash(result, ep, crash))
        return new

    # ---- stages --------------------------------------------------------

    def _generate_harness(self, entry_point: str, context: dict) -> Path | None:
        sig = self._lookup_signature(entry_point, context)
        try:
            resp = self.llm.complete_json(
                HARNESS_SYSTEM,
                f"Library: {context.get('library')}\nEntry point: {entry_point}\n"
                f"Signature/context:\n{sig}",
                max_tokens=2048,
            )
        except Exception as e:
            log.warning("harness gen failed for %s: %s", entry_point, e)
            return None
        code = resp.get("harness_c") if isinstance(resp, dict) else None
        if not code:
            return None
        # Design decision #5: harnesses persist to disk for researcher review.
        return self.save_artifact(f"harness_{entry_point}.c", code)

    def _lookup_signature(self, entry_point: str, context: dict) -> str:
        """Grep the target tree for the function declaration to ground the LLM."""
        target = Path(context.get("target", "."))
        for src in list(target.rglob("*.h")) + list(target.rglob("*.c")):
            try:
                text = src.read_text(errors="ignore")
            except OSError:
                continue
            m = re.search(rf"^[\w\s\*]*\b{re.escape(entry_point)}\s*\([^;{{]*\)", text, re.M)
            if m:
                return f"// from {src.name}\n{m.group(0)}"
        return f"// signature not found; infer from {entry_point} naming"

    def _build(self, harness: Path, context: dict) -> Path | None:
        out = harness.with_suffix("")
        target = context.get("target", ".")
        cmd = [
            "clang", "-g", "-O1",
            "-fsanitize=address,undefined,fuzzer",
            f"-I{target}", str(harness), "-o", str(out),
        ]
        # Real builds need the library's includes/objects; researchers wire
        # those via context['build_flags']. We pass them through if present.
        cmd[6:6] = context.get("build_flags", [])
        res = self.sh(cmd, timeout=300)
        if res.returncode != 0:
            self.save_artifact(f"{harness.stem}.build.log", res.stderr)
            return None
        return out

    def _fuzz(self, binary: Path, entry_point: str) -> list[Path]:
        crash_dir = self.workdir / f"crashes_{entry_point}"
        crash_dir.mkdir(exist_ok=True)
        # libFuzzer binary: run for bounded time, write crashes to crash_dir.
        res = self.sh(
            [str(binary), f"-max_total_time={self.run_seconds}",
             f"-artifact_prefix={crash_dir}/", "-print_final_stats=1"],
            timeout=self.run_seconds + 60,
        )
        self.save_artifact(f"fuzz_{entry_point}.log",
                           prefilter("fuzz", res.stdout + res.stderr))
        return sorted(crash_dir.glob("crash-*")) + sorted(crash_dir.glob("oom-*"))

    def _triage_crash(self, result: AssessmentResult, entry_point: str,
                      crash_input: Path) -> Finding:
        # Re-run the binary on the crashing input to capture sanitizer output.
        binary = self.workdir / f"harness_{entry_point}"
        res = self.sh([str(binary), str(crash_input)], timeout=60)
        san = res.stderr or res.stdout
        severity, cwe = Severity.MEDIUM, None
        for pat, sev, c in _SANITIZER_CLASS:
            if pat.search(san):
                severity, cwe = sev, c
                break

        # Map a heap-UAF in the TLS hybrid key-share path to CVE-2026-5460.
        maps_to = None
        if cwe == "CWE-416" and ("KeyShare" in san or "PqcHybrid" in san
                                 or "tls" in entry_point.lower()):
            maps_to = "CVE-2026-5460"

        f = Finding(
            title=f"Fuzzing crash in {entry_point} ({cwe or 'unclassified'})",
            phase=Phase.FUZZING,
            severity=severity,
            confidence=Confidence.CONFIRMED,  # a reproducible crash input exists
            description=f"AFL/libFuzzer produced a crashing input for {entry_point}. "
                        f"Sanitizer classified it; see evidence and saved input.",
            entry_point=entry_point,
            cwe=cwe,
            matched_target=maps_to,
            artifacts=[str(crash_input)],
        )
        f.add_evidence("sanitizer", san)
        return result.add(f)
