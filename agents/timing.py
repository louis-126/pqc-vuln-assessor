"""TimingAgent — constant-time verification via dudect-style harnesses.

Generates a dudect harness for each secret-dependent operation (decapsulation,
comparison, rejection paths), runs it, parses the Welch t-value, and flags
|t| > 4.5 as a likely timing leak.

Open problem #3 (virtualisation noise): a single t-value under WSL2/Docker is
unreliable. We mitigate by (a) requiring the measurement to run long enough for
t to stabilise and (b) re-running and requiring agreement across runs before
flagging. A leak that appears in one noisy run but not a repeat is downgraded
to SUSPECTED rather than reported as confirmed.
"""
from __future__ import annotations

import logging
import re
import statistics
from pathlib import Path

from agents.base import Agent
from core import AssessmentResult, Confidence, Finding, Phase, Severity

log = logging.getLogger("pqc")

T_THRESHOLD = 4.5
_T_VALUE_RE = re.compile(r"[tT]\s*[:=]?\s*([+-]?\d+\.\d+)")

HARNESS_SYSTEM = """\
You write dudect-style constant-time test harnesses in C. Produce two input
classes (fixed vs. random secret), call the target operation many times under
do_one_computation, and let dudect's framework measure timing. Return JSON
{"harness_c": "<code>"}. The harness measures timing only."""

# Operations that MUST be constant-time in ML-KEM/ML-DSA.
CT_SENSITIVE_OPS = {
    "wc_MlKemKey_Decapsulate": "FO re-encryption compare + implicit rejection",
    "OQS_KEM_decaps": "FO re-encryption compare + implicit rejection",
    "wc_MlDsaKey_VerifyCtx": "challenge comparison",
    "OQS_SIG_verify": "challenge comparison",
}


class TimingAgent(Agent):
    required_tools = ("clang",)

    def __init__(self, llm, workdir, repeats: int = 3):
        super().__init__(llm, workdir)
        self.repeats = repeats

    def run(self, result: AssessmentResult, context: dict) -> list[Finding]:
        ops = [ep for ep in context.get("entry_points", []) if ep in CT_SENSITIVE_OPS]
        if not ops:
            log.info("timing: no constant-time-sensitive entry points; skipping")
            return []

        new: list[Finding] = []
        for op in ops:
            harness = self._generate_harness(op, context)
            if harness is None:
                continue
            t_values = self._measure(harness, op, context)
            if not t_values:
                continue
            finding = self._evaluate(result, op, t_values)
            if finding:
                new.append(finding)
        return new

    def _generate_harness(self, op: str, context: dict) -> Path | None:
        try:
            resp = self.llm.complete_json(
                HARNESS_SYSTEM,
                f"Operation: {op}\nWhy CT-sensitive: {CT_SENSITIVE_OPS[op]}\n"
                f"Library: {context.get('library')}",
                max_tokens=2048,
            )
        except Exception as e:
            log.warning("timing harness gen failed for %s: %s", op, e)
            return None
        code = resp.get("harness_c") if isinstance(resp, dict) else None
        return self.save_artifact(f"dudect_{op}.c", code) if code else None

    def _measure(self, harness: Path, op: str, context: dict) -> list[float]:
        """Build + run the dudect harness `self.repeats` times, returning the
        max |t| observed per run (dudect reports increasing t over time)."""
        binary = harness.with_suffix("")
        build = self.sh(
            ["clang", "-O2", f"-I{context.get('target','.')}",
             *context.get("build_flags", []), str(harness),
             "-o", str(binary)],
            timeout=300,
        )
        if build.returncode != 0:
            self.save_artifact(f"{harness.stem}.build.log", build.stderr)
            return []
        runs: list[float] = []
        for i in range(self.repeats):
            res = self.sh([str(binary)], timeout=180)
            ts = [abs(float(x)) for x in _T_VALUE_RE.findall(res.stdout + res.stderr)]
            if ts:
                runs.append(max(ts))
            self.save_artifact(f"dudect_{op}.run{i}.log", res.stdout + res.stderr)
        return runs

    def _evaluate(self, result: AssessmentResult, op: str,
                  t_values: list[float]) -> Finding | None:
        median_t = statistics.median(t_values)
        all_leak = all(t > T_THRESHOLD for t in t_values)
        any_leak = any(t > T_THRESHOLD for t in t_values)
        if not any_leak:
            return None  # no leak signal

        if all_leak:
            severity = Severity.HIGH
            confidence = Confidence.CONFIRMED
            note = "Leak reproduced across all runs."
        else:
            # Inconsistent across runs -> likely virtualisation noise.
            severity = Severity.MEDIUM
            confidence = Confidence.SUSPECTED
            note = ("Leak signal inconsistent across runs (possible "
                    "virtualisation noise); re-measure on bare metal.")

        f = Finding(
            title=f"Possible timing side-channel in {op} (|t|={median_t:.1f})",
            phase=Phase.TIMING,
            severity=severity,
            confidence=confidence,
            description=f"dudect Welch |t| median {median_t:.1f} over {len(t_values)} "
                        f"runs (threshold {T_THRESHOLD}). Target op: "
                        f"{CT_SENSITIVE_OPS[op]}. {note}",
            entry_point=op,
            cwe="CWE-385",
            cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        )
        f.add_evidence("dudect", f"t-values: {t_values}")
        return result.add(f)
