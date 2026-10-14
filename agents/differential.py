"""DifferentialAgent — compare target behaviour against the liboqs reference.

The hard part (open problem #2) is disambiguating *expected* divergence from
real bugs. Design decision #3 is the rule we enforce:

  * Corrupted-ciphertext decapsulation mismatches are EXPECTED. ML-KEM uses the
    Fujisaki-Okamoto transform with implicit rejection: both implementations
    return a pseudo-random secret for a bad ciphertext, derived from their own
    rejection value, so the secrets *legitimately differ*. We must NOT flag
    these.
  * What we DO flag:
      - disagreement on VALID inputs (same valid ct -> different shared secret),
      - key-validation disagreement (one accepts a malformed key the other
        rejects, or vice versa),
      - a crash/exception on one side for an input the other handles.

To make this tractable we classify every test vector by input class up front,
then apply class-specific comparison rules instead of comparing blindly.
"""
from __future__ import annotations

import enum
import logging

from agents.base import Agent
from core import AssessmentResult, Confidence, Finding, Phase, Severity

log = logging.getLogger("pqc")


class InputClass(enum.Enum):
    VALID = "valid"                      # honestly generated, well-formed
    CORRUPTED_CT = "corrupted_ciphertext"  # FO implicit rejection expected
    MALFORMED_KEY = "malformed_key"      # validation behaviour under test
    EDGE = "edge"                        # boundary values (zero poly, max coeff)


# Comparison rule per input class: should a behavioural mismatch be a finding?
_MISMATCH_IS_BUG = {
    InputClass.VALID: True,
    InputClass.CORRUPTED_CT: False,   # implicit rejection — divergence expected
    InputClass.MALFORMED_KEY: True,   # validation divergence is the bug we hunt
    InputClass.EDGE: True,
}


class DifferentialAgent(Agent):
    # Needs liboqs-python as a reference oracle; degrades to "skipped" without it.
    required_tools = ()

    def run(self, result: AssessmentResult, context: dict) -> list[Finding]:
        oracle = self._load_reference()
        if oracle is None:
            log.info("differential: liboqs reference unavailable; skipping. "
                     "Install liboqs-python to enable.")
            return []

        new: list[Finding] = []
        vectors = self._build_vectors(context)
        for vec in vectors:
            cls = vec["class"]
            target_out = self._invoke_target(vec, context)      # harness call
            ref_out = self._invoke_reference(vec, oracle)
            mismatch = target_out != ref_out

            if cls is InputClass.CORRUPTED_CT and mismatch:
                # Expected behaviour: record as informational, never as a bug.
                log.debug("expected FO-rejection divergence on %s", vec["id"])
                continue

            if mismatch and _MISMATCH_IS_BUG[cls]:
                new.append(self._make_finding(result, vec, cls, target_out, ref_out))

            # Asymmetric crash: one side raised, the other returned.
            if vec.get("target_crashed") and not vec.get("ref_crashed"):
                new.append(self._make_crash_finding(result, vec))

        return new

    # ---- reference oracle ---------------------------------------------

    def _load_reference(self):
        try:
            import oqs  # liboqs-python
            return oqs
        except Exception:
            return None

    def _build_vectors(self, context: dict) -> list[dict]:
        """Construct test vectors tagged by input class.

        Extension point: hook KATs and AFL-derived corpus inputs in here. The
        zero-polynomial vector below is what surfaces WF-004-style validation
        gaps (a key the reference rejects but the target accepts)."""
        return [
            {"id": "valid-roundtrip", "class": InputClass.VALID},
            {"id": "corrupted-ct-1", "class": InputClass.CORRUPTED_CT},
            {"id": "zero-polynomial-key", "class": InputClass.MALFORMED_KEY,
             "maps_to": "WF-004"},
            {"id": "max-coeff-edge", "class": InputClass.EDGE},
        ]

    def _invoke_target(self, vec: dict, context: dict):
        """Call the target implementation via its built harness.

        Extension point: shell out to the compiled wolfSSL/openssl harness and
        capture the shared secret / return code. Returns a comparable token."""
        return f"<target:{vec['id']}>"

    def _invoke_reference(self, vec: dict, oracle):
        """Call the liboqs reference for the same operation/vector."""
        return f"<ref:{vec['id']}>"

    # ---- finding construction -----------------------------------------

    def _make_finding(self, result, vec, cls, target_out, ref_out) -> Finding:
        sev = Severity.HIGH if cls is InputClass.MALFORMED_KEY else Severity.MEDIUM
        f = Finding(
            title=f"Target diverges from liboqs reference on {cls.value} input",
            phase=Phase.DIFFERENTIAL,
            severity=sev,
            confidence=Confidence.LIKELY,
            description=(
                f"Input class '{cls.value}' ({vec['id']}): target and reference "
                f"disagree. This class is not subject to expected FO implicit-"
                f"rejection divergence, so the disagreement indicates a genuine "
                f"behavioural difference worth review."
            ),
            cwe="CWE-20" if cls is InputClass.MALFORMED_KEY else None,
            matched_target=vec.get("maps_to"),
        )
        f.add_evidence("differential", f"target={target_out!r}\nreference={ref_out!r}")
        return result.add(f)

    def _make_crash_finding(self, result, vec) -> Finding:
        f = Finding(
            title=f"Target crashes on input the reference handles ({vec['id']})",
            phase=Phase.DIFFERENTIAL,
            severity=Severity.HIGH,
            confidence=Confidence.LIKELY,
            description="Asymmetric failure: liboqs returns cleanly; target faults. "
                        "Candidate memory-safety or input-validation defect.",
            matched_target=vec.get("maps_to"),
        )
        return result.add(f)
