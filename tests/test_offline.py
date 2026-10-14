"""Offline smoke test — no API key or external tools required.

Exercises the data model, CVSS computation, pre-filtering, escalation-relevant
severity ordering, and the validation_status rediscovery logic.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import (  # noqa: E402
    AssessmentResult, Finding, Severity, Phase, Confidence, cvss31_base, prefilter,
)
from core.findings import default_cvss_vector  # noqa: E402


def test_cvss():
    # Known CVSS 3.1 vectors with published scores.
    # Heap UAF, network, no priv: high.
    s = cvss31_base("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert 9.0 <= s <= 9.9, s
    # Info leak only.
    s2 = cvss31_base("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N")
    assert 4.0 <= s2 <= 6.0, s2
    assert cvss31_base("garbage") == 0.0
    print("cvss ok")


def test_default_vector():
    # Every band/CWE combo must produce a parseable, non-zero vector so a
    # confirmed finding never reports 0.0 when the model omits the vector.
    for sev in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL):
        for cwe in ("CWE-208", "CWE-787", "CWE-125", "CWE-680", "CWE-330", None):
            vec = default_cvss_vector(sev, cwe)
            assert cvss31_base(vec) > 0, (sev, cwe, vec)
    # Memory-write CRITICAL should outscore a LOW side-channel.
    hi = cvss31_base(default_cvss_vector(Severity.CRITICAL, "CWE-787"))
    lo = cvss31_base(default_cvss_vector(Severity.LOW, "CWE-208"))
    assert hi > lo, (hi, lo)
    print("default vector ok")


def test_bug_classification():
    from poc.generator import _classify_bug
    assert _classify_bug("Heap buffer overflow in decode", "CWE-787") == "memory"
    assert _classify_bug("Public key accepted without canonical check", "CWE-680") == "validation"
    assert _classify_bug("Secret-dependent output disclosure", "CWE-203") == "leak"
    assert _classify_bug("Non-constant-time compare", "CWE-208") == "timing"
    # exact-number matching: CWE-203 must NOT be caught by the "20" validation set
    assert _classify_bug("info exposure", "CWE-203") == "leak"
    print("bug classification ok")


def test_spec_clause_op():
    from agents.reviewer import _op_from_clause, _op_from_code
    # Now name-based, not number-based (the old §7.2/§7.3 numbers were wrong and
    # bare section numbers are ambiguous across FIPS 203 vs 204).
    assert _op_from_clause("FIPS 203 ML-KEM.Encaps") == "encap"
    assert _op_from_clause("FIPS 203 ML-KEM.Decaps") == "decap"
    assert _op_from_clause("FIPS 204 ML-DSA.Verify §5.3") == "verify"
    assert _op_from_clause("FIPS 204 ML-DSA.Sign §5.2") == "sign"
    # bare section numbers are intentionally NOT mapped (fail-open, no demote)
    assert _op_from_clause("FIPS 203 §7.2") is None
    assert _op_from_code("OQS_KEM_decaps", "kem.c", "x=decaps()", "Decaps bug") == "decap"
    # the C5 conflict that must demote: decaps clause cited on an encaps path
    clause_op = _op_from_clause("ML-KEM.Decaps")
    code_op = _op_from_code("OQS_KEM_encaps", "", "ret = encaps(ek)", "Encaps key check")
    assert clause_op == "decap" and code_op == "encap"
    print("spec-clause op ok")


def test_timing_secret_dependence():
    from agents.reviewer import _is_timing_finding, _timing_on_public_data
    assert _is_timing_finding("Non-constant-time coefficient check", "CWE-295")
    assert _is_timing_finding("Timing leak in compare", "CWE-208")
    assert not _is_timing_finding("Buffer overflow", "CWE-787")
    # The observed false positive: non-constant-time PUBLIC-key validation → dispute.
    assert _timing_on_public_data(
        "Non-constant-time coefficient check in mlkem_check_reduced",
        "if (p[i] >= MLKEM_Q) { ret = PUBLIC_KEY_E; break; }",
        "mlkem_check_reduced loops over coefficients", None,
        "./wolfcrypt/src/wc_mlkem_poly.c")
    # A real timing bug on SECRET data → must NOT be disputed.
    assert not _timing_on_public_data(
        "Non-constant-time FO re-encryption comparison",
        "if (memcmp(ct, cmp, sz) != 0)",
        "the decaps re-encryption comparison branches on the shared secret",
        "wc_MlKemKey_Decapsulate", "wc_mlkem.c")
    # No clear operand → not disputed (falls through to the normal confirm logic).
    assert not _timing_on_public_data("Non-constant-time compare", "a == b", "", None, "x.c")
    print("timing secret-dependence ok")


def test_call_site_guard():
    from agents.reviewer import _is_call_site_only as cco
    # Weak evidence — must be flagged (the bug the old regex missed)
    assert cco("ret = wc_MlKemDecapsulate(key, ss, ct);")
    assert cco("wc_dilithium_verify(sig, len, msg, &res, key);")
    assert cco("mlkem_cmp(a, b, sz);")
    # Real logic — must NOT be flagged
    assert not cco("if (p[i] >= MLKEM_Q) return BAD;")
    assert not cco("fail |= mlkem_cmp(a, b, sz);")
    assert not cco("for (i = 0; i < n; i++) {")
    print("call-site guard ok")


def test_poc_classify_and_package():
    # The PoC stage GENERATES a documented package (no compile/run). Verify the
    # bug classifier, the fenced-code extractor, and that packages write.
    from poc.generator import _classify_bug, generate_poc_package, _extract_c
    assert _classify_bug("Heap buffer overflow", "CWE-787") == "memory"
    assert _classify_bug("Non-constant-time compare", "CWE-208") == "timing"
    # Missing-zeroization is NOT a crash bug → its own class (honest expected-result).
    assert _classify_bug("Missing zeroing of secret data", "CWE-595") == "cleanup"
    # CWE-212 must resolve to cleanup (it was double-listed in leak; that was removed).
    assert _classify_bug("Improper removal of sensitive data", "CWE-212") == "cleanup"
    assert _classify_bug("Information exposure", "CWE-200") == "leak"
    # Transport-include injection: pn_* used but no #include "poc_net.h".
    from poc.generator import _ensure_transport_include as eti
    fixed = eti('#include <stdio.h>\nint main(){pn_listen(80);}')
    assert '#include "poc_net.h"' in fixed
    assert eti('#include "poc_net.h"\npn_send(1,0,0);').count("poc_net.h") == 1
    assert "poc_net.h" not in eti('int main(){return 0;}')  # no pn_ use → untouched
    # Fenced-code extraction: clean, truncated (unterminated fence), and raw.
    assert _extract_c("```c\nint main(){return 0;}\n```") == "int main(){return 0;}"
    assert "#include <x.h>" in _extract_c("here:\n```c\n#include <x.h>\nint main(){")
    assert "#include <y.h>" in _extract_c("#include <y.h>\nint main(){}")
    assert _extract_c("sorry I can't help") == ""

    import tempfile
    from pathlib import Path
    finding = {"id": "FND-test", "title": "OOB read in decode", "cwe": "CWE-125",
               "severity": "HIGH", "spec_reference": "FIPS 203 ML-KEM.Decaps",
               "entry_point": "wc_MlKemKey_Decapsulate", "file": "wc_mlkem.c",
               "line": 1980, "description": "Reads past the buffer.",
               "proving_line": "for (i=0;i<n;i++) buf[i]=in[i];",
               "claim_justification": "no bound on n", "evidence_quote": "",
               "proposed_fix": "bound-check n"}

    # doc-only path: non-C target, no LLM calls, must still write a README.
    out = tempfile.mkdtemp()
    res = generate_poc_package(finding, "java", None, None, out, "/nonexistent", "wolfssl")
    assert res["status"] == "doc_only"
    readme = Path(res["poc_dir"]) / "README.md"
    assert readme.exists() and "The vulnerability" in readme.read_text(encoding="utf-8")

    # C path with a mock backend that returns fenced C via complete().
    class MockCode:
        model = "mock"
        def complete(self, system, user, **kw):
            return '```c\n/* poc */\n#include "poc_net.h"\nint main(){return 0;}\n```'
    out2 = tempfile.mkdtemp()
    res2 = generate_poc_package(finding, "c", MockCode(), MockCode(), out2,
                                "/nonexistent/wolfssl", "wolfssl")
    assert res2["status"] == "generated", res2
    d = Path(res2["poc_dir"])
    from poc.generator import _template_dir
    if _template_dir() is not None:
        # wolfSSL -> CLIENT-ONLY template PoC (the victim is the shared
        # tools/template server, never copied here).
        for fn in ("README.md", "client.c", "poc_net.h", "build.sh"):
            assert (d / fn).exists(), fn
        assert not (d / "server.c").exists(), "wolfSSL template PoC must be client-only"
    else:
        # no template available -> bespoke server + client
        for fn in ("README.md", "server.c", "client.c", "poc_net.h", "build.sh"):
            assert (d / fn).exists(), fn
    print("poc package (doc-only + C) ok")


def test_prefilter():
    raw = "Examining foo.c\nfoo.c:10: [4] (buffer) strcpy\nHits = 1\nLines analyzed = 50"
    out = prefilter("flawfinder", raw)
    assert "strcpy" in out
    assert "Examining" not in out and "Hits = 1" not in out
    # cap
    big = "x" * 10000
    assert len(prefilter("grep", big, cap=1000)) < 1100
    print("prefilter ok")


def test_severity_order():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM
    assert Severity.from_str("high") == Severity.HIGH
    print("severity ok")


def test_validation_status():
    # v3: manual targets removed. validation_status() returns a neutral result
    # (no ground-truth scoring). Findings stand on their own merits.
    r = AssessmentResult(target="/tmp/wolfssl", library="wolfssl")
    r.add(Finding("weak seed", Phase.STATIC, Severity.CRITICAL, Confidence.CONFIRMED,
                  "srand(time(NULL))"))
    r.add(Finding("pubkey check", Phase.STATIC, Severity.HIGH, Confidence.LIKELY,
                  "NTT not validated"))
    vs = r.validation_status()
    assert vs["total_targets"] == 0
    assert vs["rediscovered"] == 0
    assert vs["all_rediscovered"]  # vacuously true with no targets
    assert not vs["has_targets"]
    # JSON round-trips
    assert '"validation_status"' in r.to_json()
    print("validation ok (v3 neutral)")


def test_evidence_cap():
    f = Finding("t", Phase.STATIC, Severity.LOW, Confidence.SUSPECTED, "d")
    f.add_evidence("tool", "y" * 9000, cap=4000)
    assert len(f.evidence[0]) < 4200
    assert "truncated" in f.evidence[0]
    print("evidence cap ok")


def test_finding_similarity():
    from core.finding_similarity import same_bug

    def F(title, file=None, line=None, cwe=None, desc=""):
        return Finding(title, Phase.STATIC, Severity.MEDIUM, Confidence.SUSPECTED,
                       desc, file=file, line=line, cwe=cwe)

    # MUST merge: same spot, sibling CWE (203 & 208 are both observable-timing).
    assert same_bug(
        F("Non-constant-time ciphertext comparison", "./wc_mlkem.c", 1861, "CWE-203"),
        F("Variable-time memcmp on ciphertext", "./wc_mlkem.c", 1865, "CWE-208"))
    # MUST merge: same file, close lines, same defect class (weak RNG).
    assert same_bug(F("Weak RNG seed", "./random.c", 50, "CWE-330"),
                    F("Predictable seeding", "./random.c", 54, "CWE-338"))
    # MUST NOT merge: same file + same CWE but far apart, different bug.
    assert not same_bug(
        F("Hardcoded digest size", "./pk.c", 1757, "CWE-680"),
        F("Missing canonical round-trip check", "./pk.c", 1710, "CWE-680"))
    # MUST NOT merge: close lines but different defect class.
    assert not same_bug(F("Hardcoded digest size", "./pk.c", 1757, "CWE-680"),
                        F("Key export fails silently", "./pk.c", 1767, "CWE-311"))
    # MUST NOT merge: different files are always different bugs.
    assert not same_bug(F("Non-constant-time compare", "./a.c", 10, "CWE-203"),
                        F("Non-constant-time compare", "./b.c", 10, "CWE-203"))
    print("finding similarity ok")


def test_prior_findings_memo():
    from agents.researcher import _prior_findings_memo

    def F(title, file=None, line=None, cwe=None):
        return Finding(title, Phase.STATIC, Severity.HIGH, Confidence.SUSPECTED,
                       "d", file=file, line=line, cwe=cwe)

    # No prior findings -> empty memo, so single-pass runs get no injected block.
    assert _prior_findings_memo([]) == ""
    memo = _prior_findings_memo([F("Non-CT compare", "./wc_mlkem.c", 1861, "CWE-203"),
                                 F("Weak RNG seed", "./random.c", 50, "CWE-330")])
    assert "wc_mlkem.c:1861" in memo and "CWE-203" in memo and "[HIGH]" in memo
    # Bounded so it can't blow the prompt budget.
    big = [F(f"bug number {i}", "./f.c", i, "CWE-203") for i in range(50)]
    assert len(_prior_findings_memo(big, cap=15)) <= 1600
    print("prior-findings memo ok")


def test_poc_compile_loop():
    import tempfile
    from pathlib import Path
    from poc.generator import _compile_and_fix, _NO_CC

    class FakeDrafter:
        model = "fake"
        def __init__(self, reply): self.reply = reply; self.calls = 0
        def complete(self, system, user, **kw):
            self.calls += 1
            return self.reply

    start = {"server.c": "int main(void){ return undefined_sym; }\n"}
    FIX = '```c\n/*FIXED*/\nint main(void){return 0;}\n```'

    def compile_fn(out, name, inc):  # passes only once the source is fixed
        txt = (out / name).read_text()
        return ("/*FIXED*/" in txt,
                "" if "/*FIXED*/" in txt else "error: undeclared identifier")

    # Fixes within the round budget.
    out = Path(tempfile.mkdtemp()); d = FakeDrafter(FIX)
    r = _compile_and_fix(out, dict(start), ["-I."], {}, "api", d, d, 3, compile_fn)
    assert r["compiled"] is True and d.calls == 1, r
    # No compiler -> graceful skip, no model calls.
    out = Path(tempfile.mkdtemp()); d = FakeDrafter(FIX)
    r = _compile_and_fix(out, dict(start), ["-I."], {}, "api", d, d, 3,
                         lambda o, n, i: (False, _NO_CC))
    assert r["compiled"] is None and d.calls == 0, r
    # Missing header is often a hallucinated #include, so the loop ATTEMPTS a
    # fix; if it still fails it ends compiled=False with a header hint (not None).
    out = Path(tempfile.mkdtemp()); d = FakeDrafter(FIX)
    r = _compile_and_fix(out, dict(start), ["-I."], {}, "api", d, d, 2,
                         lambda o, n, i: (False, "fatal error: 'x.h' file not found"))
    assert r["compiled"] is False and "header" in r["reason"].lower(), r
    assert d.calls >= 1, r
    print("poc compile loop ok")


def test_template_applicable():
    from poc.generator import _template_applicable as ta
    # ML-KEM decap path -> the template server reaches it
    assert ta({"file": "./wolfcrypt/src/wc_mlkem.c"})
    assert ta({"file": "./wolfcrypt/src/wc_mlkem_poly.c"})
    # other components are NOT reachable through the ML-KEM template -> bespoke
    assert not ta({"file": "./wolfcrypt/src/wc_pkcs11.c"})   # PKCS#11 wrapper
    assert not ta({"file": "./wolfcrypt/src/random.c"})      # RNG
    assert not ta({"file": "./src/pk.c"})                    # classical
    print("template applicability ok")


def test_reviewer_placeholder_verdict():
    import tempfile
    from agents.reviewer import ReviewerAgent
    from core import AssessmentResult

    class FakeRev:
        model = "r"
        def complete_json(self, s, u, **k):
            # model echoes the prompt's option placeholder instead of choosing
            return {"verdict": "confirmed|disputed|needs-evidence", "reason": "echo"}

    f = Finding("Missing zeroing", Phase.STATIC, Severity.HIGH, Confidence.SUSPECTED,
                "d", file="./x.c", line=1, cwe="CWE-200")
    ReviewerAgent(FakeRev(), tempfile.mkdtemp()).run(
        AssessmentResult(target="t", library="wolfssl"), [f], context={})
    # an echoed placeholder must NOT confirm or dispute — coerced to needs-evidence
    assert f.confidence != Confidence.CONFIRMED
    assert not f.title.startswith("[DISPUTED]")
    print("reviewer placeholder verdict ok")


def test_sig_surface_filter():
    from agents.researcher import _surface_ok, _FOCUS_PASSES
    sig, kem = _FOCUS_PASSES["sig"], _FOCUS_PASSES["kem"]
    # classical crypto on the sig pass is OFF-surface (dropped)
    assert not _surface_ok(sig, "int wolfSSL_DSA_do_verify(", "./src/pk.c")
    assert not _surface_ok(sig, "int CRYPT_ECC_DSA_HashSign(", "./mcapi/crypto.c")
    assert not _surface_ok(sig, "int wc_MakeDsaKey(", "./wolfcrypt/src/dsa.c")
    assert not _surface_ok(sig, "int wc_RsaSSL_Sign(", "./wolfcrypt/src/rsa.c")
    # post-quantum signatures survive the 'dsa' substring (keep overrides drop)
    assert _surface_ok(sig, "int wc_MlDsaKey_VerifyCtx(", "./wolfcrypt/src/wc_mldsa.c")
    assert _surface_ok(sig, "int slh_dsa_verify(", "./wolfcrypt/src/wc_sphincs.c")
    assert _surface_ok(sig, "int dilithium_verify(", "./wolfcrypt/src/dilithium.c")
    # neutral helper kept; and kem focus has no filter so it keeps everything
    assert _surface_ok(sig, "int shake256_absorb(", "./wolfcrypt/src/sha3.c")
    assert _surface_ok(kem, "int wolfSSL_DSA_do_verify(", "./src/pk.c")
    print("sig surface filter ok")


def test_reviewer_per_finding():
    import tempfile
    from agents.reviewer import ReviewerAgent
    from core import AssessmentResult

    class FakeLLM:
        model = "fake-reviewer"
        def __init__(self): self.calls = 0
        def complete_json(self, system, user, **kw):
            self.calls += 1
            if "Use-after-free" in user:
                return {"verdict": "disputed", "reason": "UAF-A-reason"}
            if "Rejection Sampling" in user:
                return {"verdict": "disputed", "reason": "REJ-B-reason"}
            return {"verdict": "needs-evidence", "reason": "other"}

    A = Finding("Use-after-free in mlkem_decapsulate", Phase.STATIC, Severity.HIGH,
                Confidence.SUSPECTED, "uaf", file="./wc_mlkem.c", line=100, cwe="CWE-416")
    B = Finding("Rejection Sampling Issue", Phase.STATIC, Severity.MEDIUM,
                Confidence.SUSPECTED, "rej", file="./wc_mlkem_poly.c", line=200, cwe="CWE-680")
    llm = FakeLLM()
    ReviewerAgent(llm, tempfile.mkdtemp()).run(
        AssessmentResult(target="t", library="wolfssl"), [A, B], context={})
    # one focused call per finding, and each verdict reason stays with its finding
    assert llm.calls == 2
    assert "UAF-A-reason" in " ".join(A.evidence)
    assert "REJ-B-reason" not in " ".join(A.evidence)   # no cross-attribution
    assert "REJ-B-reason" in " ".join(B.evidence)
    print("reviewer per-finding ok")


def test_reviewer_salvage_never_disputes():
    import tempfile
    from agents.reviewer import ReviewerAgent
    r = ReviewerAgent(None, tempfile.mkdtemp())
    # A truncated/garbled review must NOT kill a finding — never 'disputed'.
    assert r._salvage_one("this does not appear to be a real bug")["verdict"] \
        == "needs-evidence"
    assert r._salvage_one('```json\n{\n "verdict": "disputed"')["verdict"] \
        == "needs-evidence"
    # A clear confirm signal still confirms.
    assert r._salvage_one('the finding is confirmed and verified')["verdict"] \
        == "confirmed"
    assert r._salvage_one('{"verdict": "confirmed", "reason": "real')["verdict"] \
        == "confirmed"
    assert r._salvage_one("") is None
    print("reviewer salvage never-disputes ok")


def test_resolution_follows_call_site():
    import tempfile
    from agents.resolution import ResolutionAgent

    class FakeLLM:
        model = "fake"
        def complete_json(self, system, user, **kw):
            return {"verdict": "needs-evidence", "reason": "still checking"}

    class FakeReg:
        def dispatch(self, name, inp):
            if name == "search_code":
                return ("./wolfcrypt/src/wc_mlkem_poly.c:1470:static int mlkem_cmp("
                        "const byte* a, const byte* b)" if inp.get("pattern") ==
                        "mlkem_cmp" else "")
            if name == "read_file":
                s, e = inp.get("start"), inp.get("end")
                if s == e:                                # cited call-site line
                    return "    ret = mlkem_cmp(buf, cmp, sz);"
                if s is not None and abs(s - 1470) < 70:  # callee body
                    return "1470: static int mlkem_cmp(...) {\n1471: return memcmp(a, b, sz);\n1472: }"
                return "1929: ret = mlkem_cmp(buf, cmp, sz);"
            return ""

    f = Finding("Non-constant-time Comparison", Phase.STATIC, Severity.HIGH,
                Confidence.SUSPECTED, "ct", file="./wolfcrypt/src/wc_mlkem.c",
                line=1929, cwe="CWE-208")
    f.add_evidence("review", "verdict=needs-evidence: [auto-demoted: "
                   "proving_line_is_call_site_only] cited only a call")
    ResolutionAgent(FakeLLM(), tempfile.mkdtemp())._resolve_one(
        f, FakeReg(), {"target": "/t"})
    ev = "\n".join(f.evidence)
    # the call into the callee was followed, surfacing the real memcmp line
    assert "callee at the cited call site" in ev and "memcmp" in ev
    print("resolution follows call-site ok")


def test_risky_line_block():
    from agents.researcher import _risky_line_block
    block = "### f ./wc_mlkem_poly.c:1470\n" + "\n".join([
        "1471:     /* memcmp in a comment must be ignored */",
        "1472:     if (memcmp(ct, ct2, ctLen) != 0) {",
        "1473:         XMEMCPY(out, in, inLen + 2);",
        "1474:         t = a % q;",
        "1475:         coeff = b / 2;",
        "1476:         memcpy(buf, src, 32);",
        "1477:         if (sk_flag) return -1;",
    ])
    out = _risky_line_block([block])
    # real smells flagged
    for ln in ("1472", "1473", "1474", "1477"):
        assert f"wc_mlkem_poly.c:{ln}" in out, ln
    # false-alarm sources NOT flagged
    for ln in ("1471", "1475", "1476"):
        assert f":{ln}" not in out, ln
    # nothing to flag -> empty string (no block injected)
    assert _risky_line_block(["### g ./x.c:1\n1: int main(void){return 0;}"]) == ""
    print("risky line block ok")


if __name__ == "__main__":
    test_cvss()
    test_default_vector()
    test_bug_classification()
    test_spec_clause_op()
    test_timing_secret_dependence()
    test_call_site_guard()
    test_poc_classify_and_package()
    test_prefilter()
    test_severity_order()
    test_validation_status()
    test_evidence_cap()
    test_finding_similarity()
    test_prior_findings_memo()
    test_poc_compile_loop()
    test_template_applicable()
    test_reviewer_placeholder_verdict()
    test_sig_surface_filter()
    test_risky_line_block()
    test_reviewer_per_finding()
    test_reviewer_salvage_never_disputes()
    test_resolution_follows_call_site()
    print("\nALL OFFLINE TESTS PASSED")
