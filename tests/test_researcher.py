"""End-to-end test of the researcher pipeline with a mock LLM (no network).

Plants a WF-004-style bug in a fake source tree, simulates the investigator
calling a tool then emitting a finding, then the reviewer confirming it, and
checks the report + validation mapping.
"""
import json, os, sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key")

from core.llm import LLMClient, ToolLoopResult

# --- mock LLM -----------------------------------------------------------
_MOCK_FINDING = {
    "title": "ML-KEM public key validation checks only coefficient range",
    "cwe": "CWE-20", "file": "wc_mlkem_poly.c", "line": 6106,
    "entry_point": "mlkem_check_public", "severity": "HIGH",
    "spec_reference": "FIPS 203 §7.2",
    "description": "mlkem_check_public only verifies p[i] >= MLKEM_Q and "
                   "never establishes NTT validity, so a zero polynomial "
                   "key is accepted.",
    "replication": "Submit an encapsulation key of all-zero coefficients.",
    "proposed_fix": "Add a decode/encode round-trip equality check.",
    "evidence_refs": ["search_code(mlkem_check_public)"],
    "evidence_quote": "if (p[i] >= MLKEM_Q) return BAD;",
}


class MockLLM(LLMClient):
    def __init__(self):
        self.config = type("C", (), {"model": "mock", "temperature": 0.2})()

    def complete(self, system, user, **kw):
        # Called by _extract_call — return the finding JSON.
        return json.dumps({"findings": [_MOCK_FINDING]})

    def run_with_tools(self, system, user, tools, dispatch, **kw):
        # Kept for --browse-loop mode; in direct-extract mode this is skipped.
        out = dispatch("search_code", {"pattern": "mlkem_check_public"})
        return ToolLoopResult(text=json.dumps({"findings": [_MOCK_FINDING]}),
                              tool_calls=[{"name": "search_code",
                                           "input": {"pattern": "mlkem_check_public"},
                                           "output": out}],
                              turns=2, stopped_reason="end_turn")

    def complete_json(self, system, user, **kw):
        # Reviewer confirms it — must now include spec_clause + proving_line.
        assert "RAW EVIDENCE" in user
        import re
        fid = re.search(r"id:\s*(FND-\w+)", user).group(1)
        return {"verdicts": [{"id": fid, "verdict": "confirmed", "severity": "HIGH",
                              "spec_clause": "FIPS 203 ML-KEM.Encaps",
                              "proving_line": "if (p[i] >= MLKEM_Q) return BAD;",
                              "claim_justification": "The loop exits on range check only; "
                                                     "no NTT validity or round-trip check follows.",
                              "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                              "reason": "Evidence shows only a range check; NTT "
                                        "validity is never established.",
                              "corrected_fix": "Round-trip decode/encode equality."}]}

# --- fake target --------------------------------------------------------
def make_target() -> Path:
    d = Path(tempfile.mkdtemp())
    (d / "wc_mlkem_poly.c").write_text(
        "int mlkem_check_public(const sword16* p) {\n"
        "  for (int i=0;i<256;i++) if (p[i] >= MLKEM_Q) return BAD;\n"
        "  return GOOD; /* missing NTT validity check */\n"
        "}\n" + "\n" * 6102
    )
    return d

# --- run ----------------------------------------------------------------
from pipeline import run_researcher_pipeline

target = make_target()
outdir = Path(tempfile.mkdtemp())
import shutil
_has_rg = shutil.which("rg") is not None
if not _has_rg:
    print("(note: ripgrep not installed; tool returns unavailable but loop still runs)")

# Without rg, _extract_call gathers no evidence and rejects all findings via
# the evidence_quote grounding check. Use browse_loop=True so the mock's
# run_with_tools path is exercised instead (it provides tool_trail evidence).
ctx = {"target": str(target), "library": "wolfssl",
       "entry_points": ["mlkem_check_public"], "max_turns": 4,
       "browse_loop": not _has_rg}

result = run_researcher_pipeline("agent-review", MockLLM(), outdir, ctx)

assert len(result.findings) == 1, result.findings
f = result.findings[0]
print("finding:", f.title)
print("confidence after review:", f.confidence.value)
print("mapped target (v3=None):", f.matched_target)
assert f.confidence.value == "confirmed", "reviewer should confirm"
# v3: manual targets removed — matched_target is always None now
assert f.matched_target is None, f"expected no target mapping, got {f.matched_target}"
assert any("verdict=confirmed" in e for e in f.evidence), "review annotation missing"
assert any("spec_clause" in e for e in f.evidence), "spec_clause not stored in evidence"
assert any("proving_line" in e for e in f.evidence), "proving_line not stored in evidence"
assert any("claim_justification" in e for e in f.evidence), "claim_justification not stored"
assert f.cvss_vector, "cvss_vector not set on confirmed finding"
assert f.cvss_score > 0, f"cvss_score should be non-zero, got {f.cvss_score}"
print("cvss:", f.cvss_vector, "->", f.cvss_score)

vs = result.validation_status()
print("rediscovered:", vs["rediscovered"], "/", vs["total_targets"])
assert (outdir / "report.md").exists() and (outdir / "report.json").exists()
print("\nAGENT-REVIEW PIPELINE OK")
