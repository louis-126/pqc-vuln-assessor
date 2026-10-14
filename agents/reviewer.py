"""ReviewerAgent — stateless evidence-only second layer.

Receives the investigator's findings PLUS their raw evidence and (in
interactive mode) a binding operator instruction. It re-derives each verdict
from evidence, cannot inherit the investigator's framing, and ANNOTATES rather
than deletes: disputed findings remain, demoted and labelled, so a wrong review
pass can never silently drop a real bug.
"""
from __future__ import annotations

import logging

from core import AssessmentResult, Confidence, Finding, Severity
from core.llm import _extract_json
from prompts import REVIEWER_SYSTEM, PKI_REVIEWER_SYSTEM

log = logging.getLogger("pqc")

_VERDICT_CONF = {
    "confirmed": Confidence.CONFIRMED,
    "disputed": Confidence.SUSPECTED,
    "needs-evidence": Confidence.SUSPECTED,
}


def _op_from_clause(clause: str) -> str | None:
    """Which crypto operation a cited spec clause is about, inferred from the
    ALGORITHM NAME (ML-KEM.Encaps/Decaps, ML-DSA.Sign/Verify). We deliberately do
    NOT map bare section numbers: they are ambiguous across standards (FIPS 203
    §5.2 = K-PKE.Encrypt vs FIPS 204 §5.2 = ML-DSA.Sign) and the table's old
    §7.2/§7.3 numbers were wrong. None = ambiguous → no demote (fail-open)."""
    c = (clause or "").lower()
    if "decap" in c:
        return "decap"
    if "encap" in c:
        return "encap"
    if "verif" in c:
        return "verify"
    if "sign" in c and "verif" not in c:
        return "sign"
    return None


def _is_call_site_only(line: str) -> bool:
    """True if the proving_line is essentially just a function call — i.e. it
    proves the callee was INVOKED, not what it does internally. Catches both the
    bare call `foo(a, b);` and the assignment form `ret = foo(a, b);` (and calls
    passing `&arg`), which the old `[<>=!&|^~]` marker regex wrongly accepted
    because the `=`/`&` matched. A line doing real work (a branch, comparison,
    bitwise accumulation, return of an expression) is NOT call-site-only."""
    import re as _re
    s = (line or "").strip().rstrip(";").strip()
    if not s:
        return False
    # Strip a single leading 'lvalue =' assignment (not ==, +=, |= etc.).
    s = _re.sub(r"^[A-Za-z_][\w.\[\]>-]*\s*=(?!=)\s*", "", s).strip()
    # What remains must be exactly one call: name(args).
    m = _re.fullmatch(r"[A-Za-z_]\w*\s*\((.*)\)", s)
    if not m:
        return False                       # has other structure → real logic
    # If the arguments themselves carry comparison/logic, it's doing work.
    if _re.search(r"==|!=|<=|>=|&&|\|\||\?", m.group(1)):
        return False
    return True


def _op_from_code(*texts: str) -> str | None:
    """Infer the operation from the finding's code context (entry point, file,
    proving line, title). Checks decap/encap before the bare 'cap' to avoid the
    substring trap. None = can't tell (no demote)."""
    blob = " ".join(t.lower() for t in texts if t)
    if "decaps" in blob or "decap" in blob or "decapsul" in blob:
        return "decap"
    if "encaps" in blob or "encap" in blob or "encapsul" in blob:
        return "encap"
    if "verify" in blob or "verif" in blob:
        return "verify"
    if ("sign" in blob or "signature" in blob) and "verif" not in blob:
        return "sign"
    return None


def _is_timing_finding(title: str, cwe: str | None) -> bool:
    """A finding about non-constant-time / timing behaviour."""
    import re as _re
    t = (title or "").lower()
    nums = set(_re.findall(r"\d+", cwe or ""))
    return (bool(nums & {"208", "385"})
            or any(w in t for w in ("constant-time", "constant time",
                                    "non-constant", "non-ct", "timing")))


# Operands that are PUBLIC (timing on them leaks nothing) vs SECRET (timing on
# them is the actual vulnerability). Used to dispute the recurring false positive
# "non-constant-time public-key validation".
_PUBLIC_DATA_MARKERS = (
    "public key", "public-key", "public_key", "pubkey", "publickey",
    "check_public", "check_reduced", "mlkem_check", "validate_public",
    "encapsulation key", "encaps key", "encapsulation-key",
)
_SECRET_DATA_MARKERS = (
    "secret", "private", "shared secret", "session key", "session secret",
    "implicit reject", "re-encrypt", "reencrypt", "re-encryption",
    "decaps", "decapsulat", "message m", "fo transform", "fo check", "mlkem_cmp",
)


def _timing_on_public_data(title: str, proving_line: str, claim: str,
                           entry_point: str | None, file: str | None) -> bool:
    """True when a timing/constant-time finding's operand is PUBLIC (public-key
    validation, etc.) and no secret operand is named — i.e. EXPECTED behaviour,
    not a leak. Constant-time only matters for SECRET data. Deliberately excludes
    the spec_clause (it may say 'Decaps' even for a public-key-validation
    subroutine reached during decapsulation, which would wrongly mask this)."""
    ctx = " ".join(s.lower() for s in
                   (title or "", proving_line or "", claim or "",
                    entry_point or "", file or ""))
    return (any(m in ctx for m in _PUBLIC_DATA_MARKERS)
            and not any(m in ctx for m in _SECRET_DATA_MARKERS))


def _spec_for_finding(f) -> str | None:
    """Best spec reference for a finding so the reviewer can be handed the actual
    FIPS requirement text. Prefer an explicit spec_reference; otherwise infer the
    standard from the algorithm/operation named in the finding. Returns a key the
    specs.fips_refs table understands ('FIPS 203' / 'FIPS 204') or None."""
    if getattr(f, "spec_reference", None):
        return f.spec_reference
    blob = " ".join(str(x).lower() for x in
                    (f.title, f.file, f.entry_point, f.description) if x)
    if any(h in blob for h in ("mlkem", "ml-kem", "ml_kem", "kyber",
                               "decap", "encap")):
        return "FIPS 203"
    # SLH-DSA must be checked BEFORE ML-DSA: 'sign'/'verify'/'signature' below
    # would otherwise capture SPHINCS+ findings and mislabel them FIPS 204.
    if any(h in blob for h in ("slhdsa", "slh-dsa", "slh_dsa", "sphincs")):
        return "FIPS 205"
    if any(h in blob for h in ("mldsa", "ml-dsa", "ml_dsa", "dilithium",
                               "signature", "verify", "sign")):
        return "FIPS 204"
    return None


def _is_pki_finding(f) -> bool:
    """True for a PKI / PROVIDER-LAYER (non-primitive) finding — one the crypto
    reviewer cannot ground in a FIPS clause and should judge on CWE merits
    instead. Generic: keyed off the discovery SURFACE the finding came from and
    its CWE class, not any library's file layout.

    Signal 1 — the finding was discovered on the `pki` surface (the multi-pass
    `discovery_pass` evidence tag records the focus label). Signal 2 — it carries
    a plumbing CWE (NPE/SSRF/DoS/alloc/config) and names no PQC algorithm, so a
    FIPS clause cannot apply to it anyway."""
    import re as _re
    ev = " ".join(getattr(f, "evidence", []) or []).lower()
    if "provider layer" in ev or "pki / provider" in ev or "pki#" in ev:
        return True
    blob = " ".join(str(x).lower() for x in
                    (f.title, f.file, f.entry_point, f.description) if x)
    has_algo = any(a in blob for a in
                   ("mlkem", "ml-kem", "ml_kem", "kyber", "mldsa", "ml-dsa",
                    "ml_dsa", "dilithium", "slhdsa", "slh-dsa", "sphincs",
                    "falcon", "xmss", "lms"))
    cwes = set(_re.findall(r"\d+", f.cwe or ""))
    # Plumbing / software-security CWEs. The fail-open family (347/636/392/295)
    # is included but only counts when NO PQC algorithm is named — an ML-DSA
    # signature-verification bypass is also CWE-347 yet belongs to the crypto
    # reviewer, and has_algo keeps it there.
    _PKI_CWE = {"476", "918", "400", "770", "15", "295", "22", "502", "611",
                "347", "636", "392"}
    return bool(cwes & _PKI_CWE) and not has_algo


class ReviewerAgent:
    def __init__(self, llm, workdir):
        self.llm = llm
        self.workdir = workdir

    def run(self, result: AssessmentResult, findings: list[Finding],
            guidance: str = "", context: dict | None = None) -> None:
        if not findings:
            log.info("reviewer: nothing to review")
            return

        # Review ONE finding per call. Batch-reviewing many findings overloads a
        # local model into crossed/templated verdicts (e.g. a constant-time
        # rationale stapled onto a use-after-free, or the SAME reason text on two
        # different findings — observed with Foundation-Sec reviewing 7 at once).
        # One focused call per finding keeps each verdict unambiguously about its
        # own finding and removes the id/position matching that scrambled them.
        for f in findings:
            v = self._review_one(f, context, guidance)
            if not v:
                f.add_evidence("review", "no verdict returned; left as suspected")
                continue
            verdict = str(v.get("verdict", "needs-evidence")).lower().strip()
            # Normalise common phrasings to our canonical verdicts.
            if verdict in ("valid", "confirm", "confirmed", "true", "real",
                           "vulnerable", "exploitable"):
                verdict = "confirmed"
            elif verdict in ("invalid", "dispute", "disputed", "false",
                             "false-positive", "not a bug", "rejected"):
                verdict = "disputed"
            elif verdict in ("unsure", "unknown", "needs-evidence",
                             "needs evidence", "uncertain"):
                verdict = "needs-evidence"
            # Anything still unrecognised — including a model that echoed the
            # prompt's "confirmed|disputed|needs-evidence" placeholder verbatim —
            # is needs-evidence, never silently kept as a raw/garbage verdict.
            if verdict not in ("confirmed", "disputed", "needs-evidence"):
                verdict = "needs-evidence"

            # Secret-dependence gate: "constant-time" only matters for SECRET
            # data. A non-constant-time finding on PUBLIC data (public-key
            # validation, public ciphertext) leaks nothing — it is EXPECTED
            # behaviour, not a vulnerability. Dispute it before the confirm
            # logic so the recurring "non-constant-time mlkem_check_* on a public
            # key" false positive can never be confirmed.
            if verdict == "confirmed" and _is_timing_finding(f.title, f.cwe) and \
                    _timing_on_public_data(
                        f.title, v.get("proving_line", ""),
                        v.get("claim_justification", ""), f.entry_point, f.file):
                verdict = "disputed"
                v["reason"] = (
                    "[auto-disputed: non-constant-time operation on PUBLIC data "
                    "(e.g. public-key validation) leaks no secret — constant-time "
                    "is only required for SECRET-dependent operations] "
                    + str(v.get("reason", "")))
                log.info("reviewer: disputed '%s' — timing on public data "
                         "(not a leak)", f.title[:60])

            # Grounding guard: a "confirmed" verdict without a quotable proving
            # line + justification is a rubber-stamp — demote it. The GROUNDING
            # differs by finding type: a PQC-primitive finding must cite a FIPS
            # clause (and pass the operation-consistency check); a PKI / provider-
            # layer finding grounds on its CWE instead, because FIPS never applies
            # to provider-layer code (requiring a FIPS clause there auto-demoted
            # every real PKI finding to needs-evidence).
            if verdict == "confirmed":
                spec_clause         = str(v.get("spec_clause", "")).strip()
                proving_line        = str(v.get("proving_line", "")).strip()
                claim_justification = str(v.get("claim_justification", "")).strip()
                missing = []
                if not proving_line:
                    missing.append("proving_line")
                if not claim_justification:
                    missing.append("claim_justification")
                # Call-site check: a proving_line that is only a function call
                # (e.g. "ret = foo(a, b)") proves nothing about foo's internals.
                if proving_line and _is_call_site_only(proving_line):
                    missing.append("proving_line_is_call_site_only")

                if _is_pki_finding(f):
                    # PKI / provider-layer: ground on the CWE, not a FIPS clause.
                    # Use the finding's CWE as the recorded grounding reference so
                    # a solid PKI finding can actually reach 'confirmed'. The FIPS
                    # operation-consistency check is crypto-only and is skipped.
                    if not spec_clause:
                        spec_clause = f.cwe or "provider-layer (CWE)"
                else:
                    if not spec_clause:
                        missing.append("spec_clause")
                    # Spec-clause / operation consistency (FIPS 203 §7.2 encaps vs
                    # §7.3 decaps; FIPS 204 sign vs verify). The single
                    # highest-value crypto rule: a finding citing a decaps/verify
                    # clause whose code context is clearly encaps/sign (or
                    # vice-versa) cited the wrong clause — a confabulation.
                    # Deterministic, fires only on a CLEAR cross-operation
                    # conflict so it never penalises ambiguity.
                    clause_op = _op_from_clause(spec_clause)
                    code_op = _op_from_code(f.entry_point, f.file, proving_line,
                                            f.title)
                    _CONFLICT = {("encap", "decap"), ("decap", "encap"),
                                 ("sign", "verify"), ("verify", "sign")}
                    if clause_op and code_op and (clause_op, code_op) in _CONFLICT:
                        missing.append(
                            f"spec_clause/operation_mismatch "
                            f"(clause={clause_op}, code={code_op})")

                if missing:
                    log.info(
                        "reviewer: demoted '%s' confirmed→needs-evidence "
                        "(missing/invalid: %s)", f.title[:60], ", ".join(missing)
                    )
                    verdict = "needs-evidence"
                    v["reason"] = (
                        f"[auto-demoted: {', '.join(missing)}] "
                        + v.get("reason", "")
                    )
                else:
                    f.add_evidence("spec_clause", spec_clause)
                    f.add_evidence("proving_line", proving_line)
                    f.add_evidence("claim_justification", claim_justification)
                    if not f.spec_reference:
                        f.spec_reference = spec_clause

            f.confidence = _VERDICT_CONF.get(verdict, Confidence.SUSPECTED)
            # Reviewer may re-score severity (annotate, never delete).
            try:
                f.severity = Severity.from_str(v.get("severity", f.severity.name))
            except (KeyError, ValueError):
                pass
            if verdict == "disputed":
                f.title = f"[DISPUTED] {f.title}"
                # demote one band but keep it in the report
                f.severity = Severity(max(0, int(f.severity) - 1))
            # CVSS vector: prefer the reviewer's vector (it reasoned about this
            # specific bug); fall back to a severity/CWE-derived vector so a
            # confirmed finding never reports 0.0. Only for confirmed findings.
            if verdict == "confirmed":
                from core.findings import cvss31_base, default_cvss_vector
                vec = str(v.get("cvss_vector", "")).strip()
                if vec and cvss31_base(vec) > 0:
                    f.cvss_vector = vec
                else:
                    f.cvss_vector = default_cvss_vector(f.severity, f.cwe)
                    f.add_evidence("cvss", "vector derived from severity/CWE "
                                   "(reviewer vector missing or unparseable)")
            f.add_evidence("review", f"verdict={verdict}: {v.get('reason','')}")
            from core import telemetry as _vt
            _vtel = _vt.get()
            if _vtel:
                _vtel.verdict(f.title, verdict)
            if v.get("corrected_fix"):
                f.add_evidence("review_fix", str(v["corrected_fix"]))

        n_conf = sum(1 for f in findings if f.confidence == Confidence.CONFIRMED)
        n_disp = sum(1 for f in findings if f.title.startswith("[DISPUTED]"))
        log.info("reviewer: %d confirmed, %d disputed, %d total",
                 n_conf, n_disp, len(findings))

    def _review_one(self, finding, context, guidance: str = "") -> dict | None:
        """Review a SINGLE finding and return its verdict dict (or None). One
        call per finding (not batched) so a local model can't cross verdicts
        between findings."""
        packet = self._packet([finding], context)
        instr = (f"\n\nBINDING OPERATOR INSTRUCTION (must follow): {guidance}"
                 if guidance else "")
        user = (
            "Review this ONE finding. Re-derive the verdict from the evidence "
            "alone — do NOT trust the finding's own claim." + instr + "\n\n" + packet
            + "\n\nReturn ONLY a JSON object for THIS finding: "
            '{"verdict": "<exactly one of: confirmed, disputed, needs-evidence>", '
            '"reason": "...", '
            '"severity": "INFO|LOW|MEDIUM|HIGH|CRITICAL", "spec_clause": "...", '
            '"proving_line": "<verbatim vulnerable line from the code>", '
            '"claim_justification": "...", "cvss_vector": "...", '
            '"corrected_fix": "..."}.'
        )
        # PKI / provider-layer findings are reviewed with the PKI-scoped prompt
        # (CWE grounding, no FIPS clause) so the crypto reviewer doesn't dispute
        # them for being "outside the ML-KEM/ML-DSA scope".
        review_system = (PKI_REVIEWER_SYSTEM if _is_pki_finding(finding)
                         else REVIEWER_SYSTEM)
        try:
            # 8192 (not 4096): a reasoning reviewer like Foundation-Sec narrates
            # before the JSON, and at 4096 it truncated mid-object — the parse
            # then failed and salvage wrongly DISPUTED a real CRITICAL finding.
            data = self.llm.complete_json(review_system, user, max_tokens=8192)
        except Exception as e:
            log.warning("reviewer: JSON parse failed for '%s' (%s) — prose salvage",
                        finding.title[:40], str(e)[:60])
            try:
                prose = self.llm.complete(review_system, user, max_tokens=8192)
            except Exception:
                prose = ""
            return self._salvage_one(prose)
        # Unwrap to a single verdict dict regardless of how the model wrapped it.
        if isinstance(data, dict):
            if "verdict" in data:
                return data
            for key in ("verdicts", "reviews", "results", "findings"):
                lst = data.get(key)
                if isinstance(lst, list) and lst and isinstance(lst[0], dict):
                    return lst[0]
            return data or None
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return data[0]
        return None

    def _salvage_one(self, prose: str) -> dict | None:
        """Single-finding verdict from narrated/truncated (non-JSON) prose.

        A parse failure is usually OUTPUT TRUNCATION, not a genuine rejection, so
        this NEVER returns 'disputed' (which would strike + demote a real
        finding). It confirms ONLY on a clear signal, else needs-evidence — so a
        truncated review can't kill a legitimate bug (resolution re-reviews it
        with full evidence). A real false positive that truncates merely survives
        as a lead until the next pass. Prefer an explicit `"verdict":"confirm…"`
        token from a partly-emitted JSON over loose prose keywords."""
        import re
        if not prose or not prose.strip():
            return None
        confirmed = (re.search(r'"?verdict"?\s*[:=]\s*"?confirm', prose, re.I)
                     or re.search(r"\b(confirmed|verified|genuine|exploitable)\b",
                                  prose, re.I))
        unsure = re.search(
            r"\b(needs?[ -]evidence|insufficient|inconclusive|uncertain|disput\w*|"
            r"false[ -]?positive|not a (?:real )?(?:bug|vuln\w*)|"
            r"does not (?:appear|seem))\b", prose, re.I)
        verdict = "confirmed" if (confirmed and not unsure) else "needs-evidence"
        return {"verdict": verdict,
                "reason": "[salvaged from a truncated/unparsed review] "
                          + " ".join(prose.split())[:160]}

    @staticmethod
    def _normalise_src_path(raw: str) -> str:
        """Turn a possibly-mangled finding path into a target-relative path.

        Local models often prepend junk (e.g. /mnt/.../wolfssl-5.7.0/) while
        still naming a real source file. We extract from the recognisable
        source-dir marker so read_file can resolve it against the real tree.
        """
        p = raw.replace("\\", "/")
        # Prefer the deepest known source root so 'wolfssl-5.7.0/wolfcrypt/src/x'
        # becomes 'wolfcrypt/src/x'.
        for marker in ("wolfcrypt/", "src/", "kem/", "sign/", "crypto/"):
            idx = p.rfind("/" + marker)
            if idx != -1:
                return p[idx + 1:]
            if p.startswith(marker):
                return p
        # Fall back: strip a leading library dir if present.
        for libmark in ("/wolfssl/", "/circl/", "/openssl/", "/liboqs/",
                        "/botan/", "/boringssl/", "/bc-java/"):
            if libmark in p:
                return p.split(libmark, 1)[1]
        return p

    def _packet(self, findings: list[Finding], context: dict | None = None) -> str:
        # v3: pull the ACTUAL code at each finding's location so the reviewer
        # can inspect the function instead of only seeing the investigator's
        # claim. A reviewer with real code can confirm/dispute; a blind reviewer
        # can only ever say "needs-evidence".
        reg = None
        target = (context or {}).get("target", "")
        if target:
            try:
                from core.tools import build_default_registry
                reg = build_default_registry(target, (context or {}).get("globs"))
            except Exception:
                reg = None

        blocks = []
        for fi, f in enumerate(findings, 1):
            ev = "\n".join(f.evidence)
            code_ctx = ""
            if reg and f.file and f.line:
                try:
                    fpath = self._normalise_src_path(f.file)
                    start = max(1, int(f.line) - 30)
                    body = reg.dispatch("read_file", {
                        "path": fpath, "start": start, "end": start + 90
                    })
                    if body and not body.startswith("[error]") and "no such file" not in body.lower():
                        code_ctx = (f"\nACTUAL CODE AT {fpath}:{f.line} "
                                    f"(lines {start}-{start+90}):\n{body}\n")
                except Exception:
                    pass

            # Inject the actual (paraphrased) FIPS 203/204 security requirement
            # so the reviewer checks the code against the STANDARD, not just its
            # own parametric memory. Previously spec_excerpt() was only wired into
            # the static-analysis path; the main agent-review pipeline never saw
            # it. Best-effort: never let a spec-lookup failure break review.
            spec_ctx = ""
            if _is_pki_finding(f):
                # PKI / provider-layer: no FIPS requirement applies. Ground the
                # reviewer on the CWE class instead so it judges the code on
                # software-security merits, not against a crypto standard.
                spec_ctx = (
                    f"\nSCOPE NOTE: this is a PKI / provider-layer finding "
                    f"({f.cwe or 'CWE'}), NOT a PQC crypto-primitive issue. Judge "
                    f"it on its software-security merits against that CWE. Do NOT "
                    f"dispute it for being 'outside the ML-KEM/ML-DSA scope' — "
                    f"provider-layer bugs are in scope here.\n")
            else:
                try:
                    from specs.fips_refs import spec_excerpt
                    ref = _spec_for_finding(f)
                    req = spec_excerpt(ref) if ref else ""
                    if req:
                        spec_ctx = (f"\nRELEVANT {ref} REQUIREMENT (paraphrased — "
                                    f"judge the code AGAINST this; a deviation is a "
                                    f"bug, conformance is not):\n{req}\n")
                except Exception:
                    spec_ctx = ""

            blocks.append(
                f"### FINDING {fi} (id: {f.id})\n"
                f"title: {f.title}\nclaimed_severity: {f.severity.name}\n"
                f"location: {f.file}:{f.line}\nentry_point: {f.entry_point}\n"
                f"cwe: {f.cwe}  spec: {f.spec_reference}\n"
                f"description: {f.description}\n"
                f"{code_ctx}{spec_ctx}\nRAW EVIDENCE:\n{ev}\n"
            )
        return "\n\n".join(blocks)