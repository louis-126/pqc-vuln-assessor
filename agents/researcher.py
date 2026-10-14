"""ResearcherAgent — the investigator (agent mode).

Runs the agentic loop: the PQC researcher persona drives tools, forms and tests
hypotheses, and emits grounded findings. In `reason` mode the same persona runs
once with no tools (it proposes what it would check instead of checking).

Findings are emitted INCREMENTALLY via <finding>...</finding> tags as each is
confirmed, so partial results are captured even if the turn budget runs out
before the final JSON block is written.
"""
from __future__ import annotations

import json
import logging
import re

from core import AssessmentResult, Confidence, Finding, Phase, Severity
from core.tools import build_default_registry
from core.finding_similarity import same_bug
from prompts import (INVESTIGATOR_SYSTEM, build_investigator_user, JAVA_PRIORS,
                     PKI_EXTRACT_SYSTEM, RESULT_USAGE_PRIOR,
                     HANDSHAKE_EXTRACT_SYSTEM)

log = logging.getLogger("pqc")

# Regex to extract inline <finding>...</finding> blocks emitted mid-response.
_FINDING_TAG_RE = re.compile(
    r"<finding>\s*(\{.*?\})\s*</finding>", re.DOTALL
)

# ---------------------------------------------------------------------------
# Multi-pass discovery surfaces. Each entry drives ONE focused investigator
# call. A single fixed call fixates on the same 1-2 findings every run; running
# one pass per surface — each with its own discover_symbols categories, callee
# role-vocabulary, entry-point anchoring, and prompt emphasis — forces the model
# to look at code the others never reach, then the findings are unioned. Which
# passes run is config-driven (config.discovery_passes()).
#
#   gather_entry_points: anchor on the curated ENTRY_POINTS (decaps/encaps-shaped
#                        — only meaningful for the kem/all surfaces).
#   categories:          discover_symbols category seeds (empty -> all).
#   callee_re:           which security-critical callees to expand one level.
#   emphasis:            surface-specific bug classes appended to the prompt.
# Everything stays library-AGNOSTIC: seeds and callees derive from the target,
# no per-library function names are hardcoded.
# ---------------------------------------------------------------------------
# BoringSSL handshake/protocol entry points, used ONLY by the "handshake" and
# "ch_consistency" focuses below (both boringssl-only — see
# config.LIBRARY_DISCOVERY_PASSES). A focus's own "entry_points" list
# overrides the global per-library one (see _extract_pass) so these two passes
# don't burn their evidence budget on the crypto-primitive entry points that
# are listed first in libraries/boringssl.toml -- gather_entry_points reads
# entry points in list order, and the char-budget trim evicts from the END, so
# whatever would be listed last is what gets silently dropped under pressure.
# Includes the MLKEM768/1024 symbols too: on the ssl/ handshake surface these
# resolve to the SSLKeyShare hybrid wrapper (ssl_key_share.cc's Encap/Decap
# combining the PQ KEM with X25519), which is genuine hybrid-key-exchange
# evidence, not noise -- kept last (lowest eviction priority; the "kem" pass
# above already covers the raw crypto/mlkem/ primitive in depth).
_HANDSHAKE_ENTRY_POINTS = [
    "do_read_second_client_hello",
    "do_read_hello_retry_request",
    "do_read_server_hello",
    "do_send_hello_retry_request",
    "UpdateForHelloRetryRequest",
    "ssl_verify_psk_binder",
    "ssl_ext_key_share_parse_clienthello",
    "ssl_ext_key_share_parse_serverhello",
    "tls1_get_shared_group",
    "do_select_session",
    "MLKEM768_decap",
    "MLKEM768_encap",
    "MLKEM768_parse_public_key",
    "MLKEM1024_decap",
]

_FOCUS_PASSES: dict[str, dict] = {
    "kem": {
        "label": "KEM decapsulation / encapsulation / keygen",
        "gather_entry_points": True,
        "categories": ["decap", "encap", "keygen"],
        "callee_re": re.compile(
            r"(cmp|compare|memcmp|equal|verify|select|cmov|cond|"
            r"seed|rng|rand|random|entropy|reduce|csubq|barrett|montgomery)",
            re.IGNORECASE),
        "emphasis": (
            "FOCUS FOR THIS PASS — ML-KEM/Kyber decapsulation & encapsulation:\n"
            "- Missing or broken FO implicit rejection: decaps MUST return a "
            "pseudorandom shared secret on re-encryption failure, never an "
            "error code or early return that reveals the mismatch.\n"
            "- Non-constant-time ciphertext re-encryption comparison "
            "(memcmp / branch / early-out on the secret comparison result).\n"
            "- Secret-dependent branching or indexing while decoding / "
            "decompressing the ciphertext or secret key.\n"
            "- Missing zeroization of the implicit-rejection seed or message.\n"
            "- Reachable panic / DoS on ANY exported entry point examined here "
            "(Verify / Unpack / Decapsulate / etc.): the function slices or "
            "indexes an attacker-controlled input buffer (e.g. sig[:Size], "
            "ct[:Size], buf[off:]) BEFORE checking its length, so a short or "
            "malformed input crashes the caller (slice-bounds panic / "
            "out-of-bounds read) instead of returning an error or false "
            "(CWE-248 / CWE-617 / CWE-125). Report this as its OWN finding EVEN "
            "WHEN the crypto acceptance logic is otherwise correct: a "
            "hybrid/composite Verify that soundly rejects on either half is "
            "still vulnerable if the length split can panic before those checks "
            "run.\n"
        ),
    },
    "sig": {
        "label": "Signature signing / verification",
        "gather_entry_points": False,
        "categories": ["sign", "verify"],
        # The sign/verify categories also match CLASSICAL DSA/ECDSA/RSA/EdDSA —
        # feeding those as evidence made the model report classical-DSA bugs
        # mislabelled "ML-DSA". Drop off-surface (non-PQC) symbols, but KEEP
        # anything clearly post-quantum (keep overrides drop, so wc_MlDsaKey_*
        # and slh_dsa_* survive the "dsa" substring match).
        "surface_drop": ("ecdsa", "ecdh", "ecc", "rsa", "dsa", "ed25519",
                         "ed448", "x25519", "curve25519", "diffie", "secp"),
        "surface_keep": ("mldsa", "ml_dsa", "dilithium", "slh_dsa", "slhdsa",
                         "sphincs", "falcon", "xmss", "lms"),
        "callee_re": re.compile(
            r"(verify|check|valid|pack|unpack|hint|decode|encode|norm|"
            r"reduce|reject|bound|cmp|memcmp)",
            re.IGNORECASE),
        "emphasis": (
            "FOCUS FOR THIS PASS — ML-DSA/Dilithium, SLH-DSA, Falcon sign & "
            "verify:\n"
            "- Verification accepting malleable or out-of-range signatures "
            "(missing coefficient-norm / infinity-norm or hint-weight bound "
            "checks before acceptance).\n"
            "- Missing length / format validation before unpacking a signature "
            "or public key (CWE-130 / CWE-680).\n"
            "- Reachable panic / DoS on an EXPORTED Verify / Unpack: the function "
            "slices or indexes an attacker-controlled signature or key buffer "
            "(e.g. sig[:SignatureSize], sig[SignatureSize:], buf[off:]) BEFORE "
            "checking its length, so a short or malformed input crashes the "
            "verifier (slice-bounds panic / out-of-bounds read) instead of "
            "returning false (CWE-248 / CWE-617 / CWE-125). Report this as its "
            "OWN finding EVEN WHEN the acceptance logic is otherwise correct: a "
            "hybrid/composite Verify that soundly rejects on either half is still "
            "vulnerable if the length split can panic before those checks run.\n"
            "- Secret-dependent timing or early-out in the signing rejection "
            "loop that leaks the per-signature nonce or the secret key.\n"
            "- Incorrect challenge / hint recomputation that allows forgery.\n"
        ),
    },
    "sampling": {
        "label": "Sampling / RNG / encoding / modular reduction",
        "gather_entry_points": False,
        "categories": ["sample", "rejection", "ntt", "reduce", "decode",
                       "encode", "rng"],
        "callee_re": re.compile(
            r"(rng|rand|random|seed|entropy|sample|reject|reduce|csubq|"
            r"barrett|montgomery|mod_q|decode|decompress)",
            re.IGNORECASE),
        "emphasis": (
            "FOCUS FOR THIS PASS — sampling, RNG, encoding, modular reduction:\n"
            "- Rejection sampling with modulo bias or a wrong acceptance bound "
            "(produces non-uniform coefficients).\n"
            "- Incomplete or incorrect modular reduction (off-by-q, unreduced "
            "values feeding the NTT, a missing conditional subtraction).\n"
            "- Weak or predictable RNG seeding (srand / time / getpid, a reused "
            "seed, or a deterministic/repeated nonce).\n"
            "- Missing bounds check before a decode / decompress loop "
            "(out-of-bounds read or write on an attacker-controlled length).\n"
        ),
    },
    # TLS 1.3 handshake / hybrid-key-exchange state machine (boringssl-only —
    # see config.LIBRARY_DISCOVERY_PASSES, which is the only place this pass
    # name gets appended to the default kem/sig/sampling list, so it never
    # runs for any other library). Distinct SCOPE from the crypto passes above
    # (like "pki"): it swaps in HANDSHAKE_EXTRACT_SYSTEM instead of the
    # PQC-restricted prompt, because that prompt explicitly forbids reporting
    # TLS-handshake bugs. "protocol_layer" additionally opts this pass into
    # the RFC-8446-field risky-line patterns (_HANDSHAKE_RISKY_PATTERNS) and
    # its own "entry_points" list overrides the global per-library one.
    "handshake": {
        "label": "TLS 1.3 handshake state machine / hybrid key exchange",
        "gather_entry_points": True,
        "scope": "handshake",
        "protocol_layer": True,
        "entry_points": _HANDSHAKE_ENTRY_POINTS,
        "categories": ["key_share", "hello_retry", "client_hello",
                       "transcript", "binder", "supported_group"],
        "callee_re": re.compile(
            r"(parse|verify|select|negotiate|duplicate|transcript|hash_message|"
            r"binder|cookie|group_id|resolve|encap|decap)",
            re.IGNORECASE),
        "emphasis": (
            "FOCUS FOR THIS PASS — TLS 1.3 handshake state machine wrapping the "
            "hybrid key exchange (ClientHello / HelloRetryRequest / "
            "ClientHello2 / transcript / binders). This is PROTOCOL LOGIC, not "
            "lattice math — the bug is a missing RFC 8446 state-machine "
            "invariant, not a coefficient bound. The headline checks for THIS "
            "pass:\n"
            "- ClientHello2 must be identical to ClientHello1 except "
            "key_share/early_data/cookie/pre_shared_key (RFC 8446 4.1.2) — is "
            "supported_groups (or anything else) actually re-checked, or does "
            "the server negotiate from ClientHello1 alone and silently ignore "
            "ClientHello2's other fields?\n"
            "- Is a SECOND HelloRetryRequest structurally impossible to "
            "accept, or merely 'the server would never send one'?\n"
            "- Duplicate KeyShareEntry for the group actually selected: "
            "rejected? HRR-selected group validated against supported_groups "
            "AND against groups already offered?\n"
            "- Does the transcript get the RFC 8446 4.4.1 synthetic "
            "message_hash swap exactly once on HRR — not skipped, not "
            "doubled?\n"
            "- EXPLOITABILITY DISCIPLINE: do not confirm 'MITM decrypts the "
            "session' from a missing consistency check alone — the Finished "
            "MAC ties transcript hash to the derived secret, so a naive "
            "single-field CH2 substitution usually fails closed. Report a "
            "missing check as INFO/LOW spec-deviation unless you can show the "
            "server ACTS on the unchecked field for something besides the key "
            "exchange itself.\n"
        ),
    },
    # Cross-message state-consistency pass (boringssl-only, see
    # config.LIBRARY_DISCOVERY_PASSES). Distinct from "handshake" above: that
    # pass looks for missing invariant CHECKS within a single function read in
    # isolation; THIS pass is specifically about state that must be CAPTURED
    # from one message and CARRIED to a later one across separate function
    # calls (do_read_second_client_hello runs long after the CH1 handler
    # returned) -- a bug class a single-function read structurally cannot see.
    # Seeded on the exact functions known to hold this state in BoringSSL.
    "ch_consistency": {
        "label": "ClientHello1→ClientHello2 cross-message state consistency",
        "gather_entry_points": True,
        "scope": "handshake",
        "protocol_layer": True,
        "entry_points": [
            "do_read_second_client_hello",   # ssl/tls13_server.cc — reads CH2
            "resolve_ecdhe_secret",          # ssl/tls13_server.cc — consumes CH1/CH2 key_share
            "do_read_hello_retry_request",   # ssl/tls13_client.cc — client-side HRR handler
            # SIBLING of do_read_hello_retry_request: the state the client
            # transitions to AFTER the first HRR, reached for any later
            # message including a would-be second HRR. The guard against a
            # second HRR can live HERE (state-machine routing) rather than as
            # a flag check in the HRR handler -- must be read alongside it.
            "do_read_server_hello",          # ssl/tls13_client.cc
            "check_ech_confirmation",        # ssl/tls13_client.cc — ECH accept/reject decision
        ],
        "categories": ["client_hello", "hello_retry", "key_share",
                       "supported_group", "ech"],
        "callee_re": re.compile(
            r"(parse|verify|select|negotiate|resolve|transcript|hash_message|"
            r"binder|cookie|group_id|confirm|accept)",
            re.IGNORECASE),
        "emphasis": (
            "FOCUS FOR THIS PASS — this is NOT a single-function bug hunt. The "
            "bug class here only exists ACROSS two messages: something is "
            "decided or recorded while processing ClientHello1 / the server's "
            "first response, and it must be RE-VALIDATED when ClientHello2 (or "
            "the second server message) arrives — reading either function in "
            "isolation looks fine; the bug is in what's missing BETWEEN them. "
            "Work this through in three explicit steps for EACH function "
            "shown:\n"
            "1. IDENTIFY THE RULE: what does RFC 8446 (4.1.2 for CH1/CH2 field "
            "equality, 4.1.4 for HRR replay, 4.4.1 for the transcript "
            "message_hash swap) require to stay IDENTICAL or be explicitly "
            "RE-CHECKED between the first and second message?\n"
            "2. IDENTIFY THE CARRIED STATE: what value, flag, or object does "
            "the code you're shown capture from the FIRST message (or set as "
            "a side effect of sending the server's first response) that is "
            "meant to constrain how the SECOND message is processed? Look for "
            "fields read off `hs` (the SSL_HANDSHAKE state struct) that were "
            "written before this function was called, not just local "
            "variables inside it.\n"
            "3. GREP FOR THE RE-VALIDATION: does the code shown, or code you "
            "can find by searching for that same state field, actually "
            "COMPARE the carried state against the second message's value "
            "before proceeding? If you only see the state being READ or "
            "OVERWRITTEN, not compared, that absence of a comparison is the "
            "finding — quote the line where the second message's value is "
            "accepted without that comparison.\n"
            "Concrete things to check with this method: does "
            "do_read_second_client_hello re-validate CH2's supported_groups, "
            "cipher_suites, session_id, compression_methods, and "
            "signature_algorithms against CH1 -- CHECK EACH ONE BY NAME, "
            "INDIVIDUALLY, do not stop once you find the first one unchecked "
            "-- or does it only use fields already resolved from CH1? A field "
            "with ZERO textual footprint anywhere in the function (never "
            "read, stored, or compared) is easy to miss precisely because "
            "there is no line to notice it on; that silence IS the finding. "
            "Report each unenforced field as its own <finding>, not folded "
            "into one general 'CH1/CH2 consistency' bug. Does "
            "resolve_ecdhe_secret use a key_share captured from CH1 without "
            "confirming it's consistent with what CH2/the HRR-selected group "
            "implies? Is a SECOND HRR rejected -- and to answer this you MUST "
            "check do_read_server_hello (the sibling function reached after "
            "the state transitions away from do_read_hello_retry_request), "
            "NOT just do_read_hello_retry_request in isolation. A guard "
            "against reprocessing a message type can be an explicit 'have I "
            "already seen this' flag INSIDE the handler, OR it can be "
            "enforced structurally by the state machine routing a repeat of "
            "that message type to a DIFFERENT function that rejects it. Both "
            "are valid guards -- do not conclude a guard is 'missing' from "
            "reading only the first function; you must also check what "
            "handles the NEXT state before claiming absence. Does "
            "check_ech_confirmation's accept/reject decision get re-derived "
            "consistently, or could a value fixed on the first pass be "
            "silently reused/skipped on a retry?\n"
        ),
    },
    # Backward-compatible single call: anchor on entry points, seed from the
    # full category set, broad callee vocabulary — reproduces the pre-multi-pass
    # behaviour. Selected via PQC_DISCOVERY_PASSES=all.
    "all": {
        "label": "All PQC surfaces (single call)",
        "gather_entry_points": True,
        "categories": [],   # empty -> discover_symbols with no category (all)
        "callee_re": re.compile(
            r"(cmp|compare|memcmp|equal|verify|select|cmov|cond|"
            r"seed|rng|rand|random|entropy|reduce|csubq|barrett|montgomery|"
            r"mod_q)",
            re.IGNORECASE),
        "emphasis": "",
    },
    # PKI / provider-layer surface (opt-in: PQC_DISCOVERY_PASSES=pki). Different
    # SCOPE from the crypto passes: it hunts fail-open verification, NPE/DoS,
    # SSRF and resource-exhaustion in certificate-path validation, revocation
    # (OCSP/CRL) and keystore loading — the LIB-01..04 bug classes. It anchors on
    # config.PKI_ENTRY_POINTS (not the crypto entry points), SKIPS the PQC-only
    # discover_symbols seeding, and uses the PKI_EXTRACT_SYSTEM prompt.
    "pki": {
        "label": "PKI / provider layer (cert-path, OCSP/CRL revocation, keystore)",
        "gather_entry_points": True,
        "skip_discovery": True,   # discover_symbols is PQC-filtered; anchor on
                                  # PKI entry points + callee expansion instead
        "repeat": 3,              # multi-pass with cross-pass memory to beat the
                                  # single-call fixation (a lone pass stops at the
                                  # first 5-6 bugs and skips subtler fail-opens)
        "categories": [],
        "callee_re": re.compile(
            r"(verif|valid|check|equal|open|connect|inputstream|generatecrl|"
            r"iteration|trusted|tbscert|geturl|touri|initverify|signature|"
            r"decode|parse|getinstance|responder|revocation)",
            re.IGNORECASE),
        "emphasis": (
            "FOCUS FOR THIS PASS — PKI / provider-layer software-security bugs:\n"
            "- OCSP / signature verification that fails OPEN (a false or failed "
            "check is not enforced, so an invalid response is accepted).\n"
            "- Certificate-path validation dereferencing a documented-nullable "
            "value (e.g. getTrustedCert()) with no guard -> NPE / DoS.\n"
            "- CRL / AIA fetch built from an attacker-controlled URI with no "
            "scheme restriction (SSRF) or no response-size cap (memory DoS).\n"
            "- Keystore / PKCS#12 load doing attacker-count-driven iteration work "
            "before authentication, or a cap sourced from an overridable "
            "system property.\n"
        ),
        "scope": "pki",
    },
}


# ---------------------------------------------------------------------------
# Full-method (brace-matched) evidence extraction (open improvement #1).
# A fixed line window clips exactly the parts of a method that make a bug
# visible: a FAIL-OPEN needs EVERY exit path (a swallowed exception, an empty
# catch, a fall-through after a failed sub-check), and a NULL-DEREF needs the
# call site AND the (absent) guard together. Walking braces returns the WHOLE
# enclosing method around an anchor line instead of a window. Generic to brace
# languages (C/C++/Java/Go/Rust); callers fall back to a fixed window when this
# returns None (non-brace source, minified, or a method past the size cap).
# ---------------------------------------------------------------------------
_CTRL_HEAD = {"if", "for", "while", "switch", "try", "catch", "else", "do",
              "synchronized", "finally", "static", "return", "new", "sizeof"}


def _debrace(line: str) -> str:
    """Drop string/char literals and line comments so a { or } inside them is
    not counted when brace-matching. Block comments are not handled (rare around
    braces; the size cap + fallback bound any mis-match)."""
    out = []
    i = 0
    in_s = None
    while i < len(line):
        c = line[i]
        if in_s:
            if c == "\\":
                i += 2
                continue
            if c == in_s:
                in_s = None
            i += 1
            continue
        if c in ("'", '"'):
            in_s = c
            i += 1
            continue
        if c == "/" and i + 1 < len(line) and line[i + 1] == "/":
            break                       # rest of the line is a comment
        out.append(c)
        i += 1
    return "".join(out)


def _brace_match(rows: list, start_j: int):
    """Index in `rows` of the line closing the block opened at/after start_j,
    or None if the window does not contain the matching brace."""
    depth = 0
    started = False
    for k in range(start_j, len(rows)):
        for ch in _debrace(rows[k][1]):
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
                if started and depth == 0:
                    return k
    return None


def _method_header_start(rows: list, bi: int):
    """If the block whose opening '{' is on row `bi` is a METHOD / constructor
    body, return the row index where its signature STARTS (spanning a multi-line
    signature); else None. Rejects control blocks (if/for/try/...), static
    initializers, anonymous classes (`new X() {`), lambdas and array literals."""
    parts = []                          # debraced header lines, nearest first
    start_j = bi
    for j in range(bi, max(-1, bi - 8), -1):
        c = _debrace(rows[j][1])
        # A prior statement / block boundary means we've walked past this header.
        if j != bi and (";" in c or "}" in c or c.rstrip().endswith("{")):
            break
        parts.append(c)
        start_j = j
        joined = " ".join(reversed(parts))
        if joined.count("(") and joined.count("(") == joined.count(")"):
            break                       # whole (possibly multi-line) param list
    joined = " ".join(reversed(parts))
    m = re.search(r"([A-Za-z_]\w*)\s*\(", joined)
    if not m or m.group(1) in _CTRL_HEAD:
        return None
    if re.search(r"\bnew\s+$", joined[:m.start()]):
        return None                     # anonymous class body, not a method
    # A real signature: params close, then (optional throws) then the brace.
    if not re.search(r"\)\s*(?:throws [\w.,<>\[\] ]+)?\s*\{?\s*$", joined):
        return None
    # A method/constructor has a return type / modifier (or throws) — a bare
    # `foo() {` with nothing before the name is not valid at class scope, so this
    # also filters stray call-shaped fragments.
    if not joined[:m.start()].strip() and "throws" not in joined:
        return None
    return start_j if joined.count("(") else bi


def _read_enclosing_method(reg, fpath: str, lineno: int,
                           max_method_lines: int = 550):
    """(start_lineno, numbered_body) of the full brace-matched method enclosing
    (fpath, lineno), or None to signal the caller should use a fixed window
    (non-brace source, minified code, or a method larger than the cap).

    `max_method_lines` is normally passed by the caller as a budget-derived,
    backend-aware value (see _extract_pass); the default here is only a standalone
    fallback for direct callers/tests.

    Walks the brace nesting: computes the stack of open blocks enclosing the
    anchor, then from the INNERMOST outward returns the first that is a real
    method body — so an anchor deep inside an if/try inside the method still
    resolves to the whole method, and multi-line signatures are handled.

    Reads the file DIRECTLY (not through reg.dispatch, whose 6000-char output cap
    truncates a several-hundred-line window and would drop the anchor and the
    method's tail — exactly the exit paths we need)."""
    from pathlib import Path as _P
    try:
        base = _P(reg.target).resolve()
        p = (base / fpath).resolve()
        p.relative_to(base)             # guard: never read outside the tree
        file_lines = p.read_text(errors="ignore").splitlines()
    except Exception:
        return None
    # Window must scale with the cap: the anchor can sit anywhere inside the
    # method, so to bracket a method up to `max_method_lines` long we must read
    # that far in BOTH directions (signature above, closing brace below). A
    # fixed +340 below would clip the tail of a large method (e.g. a 480-line
    # engineValidate whose closing brace is ~400 lines past the anchor) and the
    # brace-match would fail. Direct read is uncapped, so this is cheap.
    _reach = max_method_lines + 40
    lo = max(1, lineno - _reach)
    hi = min(len(file_lines), lineno + _reach)
    rows = [(i, file_lines[i - 1]) for i in range(lo, hi + 1)]  # (abs_lineno, content)
    if not rows:
        return None
    anchor = len(rows) - 1
    for i, (n, _c) in enumerate(rows):
        if n >= lineno:
            anchor = i
            break
    # Open '{' row indices still unclosed at the start of the anchor line.
    stack = []
    for k in range(0, anchor):
        for ch in _debrace(rows[k][1]):
            if ch == "{":
                stack.append(k)
            elif ch == "}" and stack:
                stack.pop()
    for bi in reversed(stack):          # innermost enclosing block first
        sj = _method_header_start(rows, bi)
        if sj is None:
            continue
        end = _brace_match(rows, sj)
        if end is None or end < anchor:
            continue
        if (rows[end][0] - rows[sj][0]) > max_method_lines:
            return None
        body = "\n".join(f"{n}: {c}" for n, c in rows[sj:end + 1])
        return rows[sj][0], body
    return None


class ResearcherAgent:
    def __init__(self, llm, workdir, use_tools: bool = True, max_turns: int = 16):
        self.llm = llm
        self.workdir = workdir
        self.use_tools = use_tools
        self.max_turns = max_turns

    def run(self, result: AssessmentResult, context: dict,
            guidance: str = "", direct_extract: bool = True) -> list[Finding]:
        """Run the investigator.

        direct_extract=True (default): skip the agentic browse loop entirely and
        go straight to _extract_call. This is the recommended path for
        reasoning models (deepseek-r1, etc.) that don't benefit from the
        multi-turn tool loop — they read code better in a focused single call.
        The browse loop is preserved for models that natively drive tools well.
        """
        if direct_extract:
            from core import telemetry as _t
            _tel = _t.get()
            if _tel:
                _tel.agent("investigator", f"direct-extract on {context['library']} (model: {getattr(self.llm,'model','?')})")
            findings = self._extract_call(result, [], context)
            from core import telemetry as _tlm3
            _tel3 = _tlm3.get()
            if _tel3:
                for f in findings:
                    _tel3.finding(f.title, f.severity.name,
                                  f"{f.file}:{f.line}" if f.file else "")
            log.info("investigator (direct) emitted %d finding(s)", len(findings))
            return findings

        user = build_investigator_user(
            context["target"], context["library"],
            context.get("entry_points", []), guidance,
        )

        if self.use_tools:
            reg = build_default_registry(context["target"], context.get("globs"))
            # v3: dynamic symbol discovery — explore beyond hardcoded entry points
            from core.tools import register_discovery_tool
            register_discovery_tool(reg, context["target"], context.get("globs"),
                                     context.get("library", ""))
            # v3 stage 4: Joern CPG data-flow slicing. Default-OFF (opt-in via
            # PQC_ENABLE_JOERN=1) until its CLI contract is verified on the host
            # — only register the tool when actually enabled.
            from core.joern_slice import register_joern_tool, joern_enabled
            if joern_enabled():
                register_joern_tool(reg, context["target"])
            # v2: register Go tools if targeting a Go library
            if context.get("lang") == "go":
                from core.tools import register_go_tools
                register_go_tools(reg, context["target"])
            elif context.get("lang") == "java":
                from core.tools import register_java_tools
                register_java_tools(reg, context["target"])
            log.info("investigator tools available: %s", ", ".join(reg.names()))

            from core import telemetry
            _tel = telemetry.get()
            if _tel:
                _tel.agent("investigator", f"exploring {context['library']} (model: {getattr(self.llm,'model','?')})")

            def on_event(kind, payload):
                if kind == "tool_call":
                    log.debug("  tool> %s %s", payload["name"],
                              {k: v for k, v in payload["input"].items()})
                    if _tel:
                        _tel.tool(payload["name"], payload.get("input", {}))

            # Route tool calls through the per-run cache (when --cache-reads
            # is on) so repeated IDENTICAL calls — e.g. the model looping on
            # discover_symbols(decap) — return instantly instead of re-running
            # ripgrep / Joern each time. (Previously reg.dispatch bypassed the
            # cache entirely, so hit-rate was always 0%.)
            _tool_cache = context.get("tool_cache")

            def dispatch(name, tool_input):
                if _tool_cache is not None:
                    hit = _tool_cache.get(name, tool_input)
                    if hit is not None:
                        return hit
                out = reg.dispatch(name, tool_input)
                if _tool_cache is not None:
                    _tool_cache.set(name, tool_input, out)
                return out

            loop = self.llm.run_with_tools(
                INVESTIGATOR_SYSTEM, user, reg.schemas(), dispatch,
                max_turns=self.max_turns, max_tokens=8192, on_event=on_event,
                cache_system=context.get("cache_system", False),
            )
            log.info("investigator ran %d turn(s), %d tool call(s)",
                     loop.turns, len(loop.tool_calls))
            raw_text = loop.text
            tool_trail = loop.tool_calls
        else:
            raw_text = self.llm.complete(INVESTIGATOR_SYSTEM, user, max_tokens=4096)
            tool_trail = []

        findings = self._parse(raw_text, result, tool_trail)

        # v3: two-call architecture. If the exploration turn(s) produced no
        # parseable findings (common with MoE models that drift into chat mode
        # after tool turns), run a SEPARATE focused extraction call. It gets the
        # exact code the investigator read and has exactly one job: output
        # findings as JSON. No tools, no role confusion.
        if not findings and tool_trail:
            log.info("investigator: no findings parsed from exploration — "
                     "running focused extraction call")
            from core import telemetry as _t
            _tel2 = _t.get()
            if _tel2:
                _tel2.thinking("exploration yielded no structured findings — running focused extraction")
            findings = self._extract_call(result, tool_trail, context)

        from core import telemetry as _t3
        _tel3 = _t3.get()
        if _tel3:
            for f in findings:
                _tel3.finding(f.title, f.severity.name,
                              f"{f.file}:{f.line}" if f.file else "")
        log.info("investigator emitted %d finding(s)", len(findings))
        return findings

    def run_compare(self, result: AssessmentResult, context: dict,
                    models: list[str]) -> list[Finding]:
        """Multi-model A/B discovery. Runs the extraction step once per model on
        the SAME deterministically-gathered evidence (entry-point bodies + Joern
        slices), tags each finding with the model that produced it, and unions
        them. Models load SERIALLY so a 16GB card is never over-committed."""
        from core.llm import OllamaBackend
        from core import telemetry as _t
        _tel = _t.get()
        all_findings: list[Finding] = []
        for m in models:
            if _tel:
                _tel.agent(f"discovery [{m}]", "analysing shared evidence")
            try:
                llm_m = OllamaBackend(model=m)
            except Exception as e:
                log.warning("compare: cannot load model %s: %s", m, e)
                if _tel:
                    _tel.note(f"{m}: unavailable ({e})")
                continue
            agent_m = ResearcherAgent(llm_m, self.workdir, use_tools=False,
                                      max_turns=self.max_turns)
            fm = agent_m._extract_call(result, [], context)
            for f in fm:
                f.discovered_by = m
                f.add_evidence("discovered_by", m)
                if _tel:
                    _tel.finding(f"{f.title}  [{m}]", f.severity.name,
                                 f"{f.file}:{f.line}" if f.file else "")
            log.info("compare: %s produced %d grounded finding(s)", m, len(fm))
            if _tel:
                _tel.note(f"{m}: {len(fm)} grounded finding(s)")
            all_findings.extend(fm)
        log.info("compare: %d total finding(s) across %d model(s)",
                 len(all_findings), len(models))
        return all_findings

    def _extract_call(self, result: AssessmentResult, tool_trail: list[dict],
                      context: dict) -> list[Finding]:
        """Multi-pass discovery orchestrator.

        Instead of ONE fixed extraction call (which fixates on the same 1-2
        findings every run), run one focused pass per crypto SURFACE
        (kem / sig / sampling — see _FOCUS_PASSES), each over surface-biased
        evidence with its own prompt emphasis, then UNION the grounded findings.
        A bug surfaced by more than one pass is kept once and tagged as
        cross-pass corroborated (a self-consistency signal). Which passes run is
        config-driven (config.discovery_passes(), env PQC_DISCOVERY_PASSES — set
        it to "all" for the original single call). Each pass is a full
        investigator model call, so N passes ≈ N× investigator runtime.
        """
        import config as _cfg
        names = _cfg.discovery_passes(context.get("library", ""))
        focuses = []
        for n in names:
            spec = _FOCUS_PASSES.get(n)
            if spec is None:
                log.warning("discovery: unknown pass '%s' (known: %s) — skipping",
                            n, ", ".join(_FOCUS_PASSES))
                continue
            # A focus may request MULTIPLE passes over the same evidence (spec
            # 'repeat'). Each re-run receives cross-pass memory ("already reported
            # X — find DIFFERENT bugs"), which beats the single-call fixation that
            # otherwise makes a one-shot pass stop at the first 5-6 findings and
            # skip subtler ones (e.g. a fail-open lost to a busier finding).
            _rep = max(1, int(spec.get("repeat", 1)))
            for _r in range(_rep):
                focuses.append((f"{n}#{_r + 1}" if _rep > 1 else n, spec))
        if not focuses:
            log.warning("discovery: no valid passes in %s — falling back to 'all'",
                        names)
            focuses = [("all", _FOCUS_PASSES["all"])]

        from core import telemetry as _t
        _tel = _t.get()
        multi = len(focuses) > 1
        if multi:
            log.info("multi-pass discovery: %d pass(es) [%s] — each is a full "
                     "investigator model call",
                     len(focuses), ", ".join(n for n, _ in focuses))
            if _tel:
                _tel.note(f"multi-pass discovery: {len(focuses)} passes "
                          f"({', '.join(n for n, _ in focuses)}); each is a "
                          f"separate full model call")

        union: list[Finding] = []
        seen: dict[tuple, Finding] = {}
        for _i, (name, focus) in enumerate(focuses, 1):
            if multi and _tel:
                _tel.agent("investigator",
                           f"pass [{_i}/{len(focuses)}] '{name}' — {focus['label']}")
            pass_findings = self._extract_pass(result, tool_trail, context, focus,
                                               prior_findings=list(union))
            log.info("discovery pass [%d/%d] '%s': %d grounded finding(s)",
                     _i, len(focuses), name, len(pass_findings))
            for f in pass_findings:
                if multi:
                    f.add_evidence("discovery_pass", f"{name} — {focus['label']}")
                if f.line is not None:
                    key = (_basename(f.file or ""), int(f.line),
                           (f.cwe or "").lower())
                else:
                    key = (f.title.strip().lower(), _basename(f.file or ""))
                if key in seen:
                    # Same bug from another pass: a strong self-consistency
                    # signal. Keep the first, annotate it, and drop the duplicate
                    # so it is not double-reported downstream.
                    kept = seen[key]
                    kept.add_evidence("cross_pass_corroboration",
                                      f"independently surfaced in '{name}' pass")
                    log.info("discovery: '%s' corroborated across passes (via %s)",
                             f.title[:50], name)
                    if f in result.findings:
                        result.findings.remove(f)
                    continue
                # Exact-key miss: catch SEMANTIC near-duplicates — the same bug
                # reported with a slightly different line, a sibling CWE, or
                # different wording — so the union doesn't double-count it.
                dup = next((u for u in union if same_bug(u, f)), None)
                if dup is not None:
                    dup.add_evidence("cross_pass_corroboration",
                                     f"near-duplicate merged from '{name}' pass "
                                     f"(was: {f.title[:60]})")
                    log.info("discovery: '%s' merged as near-duplicate of '%s' "
                             "(via %s)", f.title[:40], dup.title[:40], name)
                    if f in result.findings:
                        result.findings.remove(f)
                    continue
                seen[key] = f
                union.append(f)
        if multi:
            log.info("multi-pass discovery: %d unique finding(s) across %d passes",
                     len(union), len(focuses))
        return union

    def _extract_pass(self, result: AssessmentResult, tool_trail: list[dict],
                      context: dict, focus: dict,
                      prior_findings: list[Finding] | None = None) -> list[Finding]:
        """One focused extraction call over a single crypto SURFACE.

        `focus` (an entry from _FOCUS_PASSES) controls the evidence gathered —
        configured entry points (focus-gated), discover_symbols categories, and
        the role-callee regex — and the prompt emphasis. Feeds the gathered code
        to a fresh, narrowly-scoped prompt whose only output is grounded findings
        JSON. The grounding / anti-hallucination checks below are surface-neutral.
        """
        from prompts import INVESTIGATOR_SYSTEM
        from core.tools import build_default_registry

        # Assemble everything the investigator actually read.
        evidence_blocks = []
        for c in tool_trail:
            if c["name"] in ("read_file", "search_code", "discover_symbols",
                             "find_callers", "run_semgrep", "run_flawfinder",
                             "run_cppcheck", "run_pmd", "run_spotbugs"):
                evidence_blocks.append(
                    f"### Tool: {c['name']}({_fmt(c['input'])})\n{c['output']}"
                )

        # v3: auto-gather generous windows around the surface's functions for
        # breadth. The investigator often skims; this guarantees the extractor
        # sees the full function bodies of the high-value targets.
        reg = build_default_registry(context["target"], context.get("globs"))
        entry_points = context.get("entry_points", [])
        import re as _re
        # Test/doc/example matches are NOT the implementation. Feeding them to the
        # model is why earlier runs analysed unit-test calls and doxygen comments
        # instead of the real decaps/verify code. Rank matches and read the
        # implementation body, not the first alphabetical hit (doc/ , tests/).
        # Centralised, per-library-aware blacklist of non-implementation
        # files (tests/docs/examples/fuzzers/build+code-gen tooling/bindings/
        # CLI). Single source of truth in config.py; generic + this library's
        # extras. Matched case-insensitively as path substrings.
        import config as _cfg
        _NOISE = tuple(m.lower()
                       for m in _cfg.non_impl_markers(context.get("library", "")))

        # Per-call evidence budget (backend-aware) and the largest method we
        # inline WHOLE. The cap is budget-derived (self-scaling) but CEILINGED at
        # 400 lines. Empirically, letting a big-context backend inline very large
        # methods (a 445-line engineValidate + a 168-line check() + ...) ballooned
        # the evidence to the 150K ceiling, forced trimming, and DROWNED the
        # signal — findings fell 11->6 and the LIB-01 fail-open that a leaner run
        # caught was lost. ~400 lines is the sweet spot: a mid-size decisive
        # method (check(), 168) inlines whole while oversized glue (engineValidate)
        # stays a window. The budget-derived floor still scales DOWN for small
        # local budgets (Ollama ~48K -> ~320). Generic: no per-library number.
        _budget = _cfg.evidence_char_budget(
            _cfg.backend_evidence_budget(context.get("backend")))
        _AVG_CHARS_PER_LINE = 50
        _WHOLE_METHOD_LINE_CEILING = 400
        _method_line_cap = min(_WHOLE_METHOD_LINE_CEILING,
                               max(150, (_budget // 3) // _AVG_CHARS_PER_LINE))

        # Exclude globs for symbol RESOLUTION / caller searches. Test / example /
        # generated / multi-release files pollute a common-name search (e.g.
        # 'checkCertificate' returned 55 hits, ALL test/jdk1.x, which filled the
        # 6000-char search output cap and truncated the real implementation).
        # Excluding them at the ripgrep level lets the real definition/caller
        # survive the cap. Library- and language-agnostic.
        _RESOLVE_EXCLUDES = [
            "**/test/**", "**/tests/**", "**/testsuite/**", "**/testdata/**",
            "**/jdk1.*/**", "**/example*/**", "**/examples/**", "**/demo*/**",
            "**/benchmark*/**", "**/bench/**", "**/fuzz*/**",
            "**/*Test.java", "**/*Tests.java", "**/*_test.*",
        ]

        # The PKI surface anchors on the provider-layer entry points (cert-path /
        # OCSP/CRL / keystore), not the crypto entry points.
        if focus.get("scope") == "pki":
            entry_points = _cfg.pki_entry_points(context.get("library", ""))
        # A focus may pin its OWN entry-point list (e.g. the boringssl-only
        # "handshake"/"ch_consistency" passes) instead of the full per-library
        # list. Without this, gather_entry_points pulls in the crypto-primitive
        # entry points too (they're listed first in libraries/<lib>.toml),
        # wasting evidence-budget chars on them and risking this pass's own
        # most-relevant entry points being evicted by the char-budget trim
        # (evidence_blocks.pop() removes from the END — see below).
        elif focus.get("entry_points"):
            entry_points = focus["entry_points"]

        # Helper: rank search hits for a symbol and return the best
        # (fpath, lineno) that looks like the IMPLEMENTATION definition. Reused
        # for both entry points and callee expansion. Library- and language-
        # neutral: scores by source-file extension, source-tree location, and a
        # definition-ish signature — no per-library names baked in.
        def _rank_impls(symbol: str):
            """Ranked implementation candidates for a symbol: list of
            (score, fpath, lineno), best first, from search_code (test/generated
            files excluded at the ripgrep level so the real definition isn't
            truncated away by the output cap)."""
            loc = reg.dispatch("search_code",
                               {"pattern": symbol, "exclude": _RESOLVE_EXCLUDES})
            cands = []
            for _ln in loc.splitlines():
                mm = _re.match(
                    r"([^\s:]+\.(?:c|h|cc|cpp|cxx|go|java)):(\d+):(.*)", _ln)
                if not mm:
                    continue
                # Forward slashes so the _NOISE substring filters (e.g. '/jdk1.',
                # '/test/') actually match on Windows, and so the returned path is
                # JSON-safe when the model cites it.
                fp = mm.group(1).replace("\\", "/")
                if any(n in fp.lower() for n in _NOISE):
                    continue
                content = mm.group(3)
                if "{%" in content or "{{" in content or "<%" in content:
                    continue            # code-generation template, not code
                fpl = fp.lower()
                score = 0
                if fpl.endswith((".c", ".cc", ".cpp", ".cxx", ".go",
                                 ".java", ".rs")):
                    score += 2
                if any(seg in fpl for seg in
                       ("src/", "/lib/", "internal/", "crypto/")):
                    score += 2          # under some source tree (any layout)
                if (_re.search(_re.escape(symbol) + r"\s*\(", content)
                        and "=" not in content.split(symbol)[0]):
                    score += 3          # definition-ish (call with no assign)
                cands.append((score, fp, int(mm.group(2))))
            cands.sort(key=lambda c: c[0], reverse=True)
            return cands

        def _best_impl(symbol: str):
            cands = _rank_impls(symbol)
            return (cands[0][1], cands[0][2]) if cands else None

        def _best_impls(symbol: str, n: int = 2):
            """The best implementation PLUS same-class sibling variants (best
            first, up to n). Many libraries ship the same class in multiple real
            variants — the same file BASENAME under different modules/packages
            (e.g. jce.provider vs pkix.jcajce CrlCache.java) — and picking just one
            causes a run-to-run 'which variant did we happen to gather' coverage
            gap. We add a sibling only when it shares the top hit's basename AND a
            comparable score, so an UNRELATED class that merely has a method of the
            same name (e.g. getCrls() on an ASN.1 accessor) is never pulled in.
            Library- and language-agnostic; bounded by n."""
            cands = _rank_impls(symbol)
            if not cands:
                return []
            top_score, top_fp, top_ln = cands[0]
            top_base = top_fp.rsplit("/", 1)[-1].lower()
            out = [(top_fp, top_ln)]
            seen = {top_fp.lower()}
            for _sc, _fp, _ln in cands[1:]:
                if len(out) >= n:
                    break
                if _fp.lower() in seen:
                    continue
                if (_fp.rsplit("/", 1)[-1].lower() == top_base
                        and _sc >= top_score - 1):
                    seen.add(_fp.lower())
                    out.append((_fp, _ln))
            return out

        # Seed bodies feed callee expansion below: entry-point bodies (when this
        # focus anchors on them) plus the discovered bodies.
        seed_bodies = []   # (label, fpath, body)

        # 1. Configured entry points — only for focuses that anchor on them. The
        # curated ENTRY_POINTS are decaps/encaps-shaped, so the sig/sampling
        # passes derive their surface from discover_symbols instead.
        # Level-A transparency: record which curated entry points RESOLVED to real
        # code in the target tree (so a clean run can show what it actually looked
        # at, vs symbols that don't exist in this library's layout).
        _ep_cov: dict[str, dict] = {}
        if focus.get("gather_entry_points"):
            # How many distinct-file variants of each entry point to gather. The
            # PKI/provider surface has the same class in multiple modules (prov vs
            # pkix, base vs _8), so 2 avoids the run-to-run variant lottery; crypto
            # entry points are usually unique per library, so 1 keeps those passes
            # lean. (_best_impls is generic — raise for any duplicated-symbol lib.)
            _ep_variants = 2 if focus.get("scope") == "pki" else 1
            for ep in entry_points:
                _resolved_ep = False
                try:
                    for fpath, lineno in _best_impls(ep, _ep_variants):
                        # Forward slashes: the model copies this path into its JSON
                        # 'file' field; Windows backslashes there become invalid
                        # JSON escapes (\c, \s, \b...) that break parsing.
                        fpath = fpath.replace("\\", "/")
                        # Full enclosing method (all exit paths visible), with a
                        # fixed window as fallback when brace-matching can't
                        # bracket one.
                        _m = _read_enclosing_method(reg, fpath, lineno,
                                                    _method_line_cap)
                        if _m:
                            lineno, body = _m
                        else:
                            start = max(1, lineno - 10)
                            body = reg.dispatch("read_file", {
                                "path": fpath, "start": start, "end": start + 95
                            })
                        evidence_blocks.append(
                            f"### {ep} (implementation) {fpath}:{lineno}\n{body}")
                        seed_bodies.append((ep, fpath, body))
                        if not _resolved_ep:
                            _ep_cov[ep] = {"resolved": True,
                                           "file": f"{fpath}:{lineno}",
                                           "lines": body.count("\n") + 1}
                            _resolved_ep = True
                except Exception:
                    continue
                if not _resolved_ep:
                    _ep_cov.setdefault(
                        ep, {"resolved": False, "file": None, "lines": 0})

        # 2. Library-AGNOSTIC seeding, narrowed to THIS focus's categories so
        # each pass pulls a DIFFERENT surface (decap/encap vs sign/verify vs
        # sample/rng/reduce). Enumerates PQC-relevant function DEFINITIONS across
        # the whole tree via discover_symbols and reads their bodies. The
        # hardcoded entry-point names are wolfSSL-shaped and resolve to little on
        # other layouts (liboqs/botan/circl); this derives seeds from the TARGET.
        try:
            from core.tools import register_discovery_tool
            register_discovery_tool(reg, context["target"], context.get("globs"),
                                     context.get("library", ""))
            cats = focus.get("categories") or [""]
            disc_lines: list[str] = []
            # skip_discovery: the PKI surface anchors purely on its entry points +
            # callee expansion; discover_symbols is PQC-filtered and would pull
            # crypto code into an otherwise provider-layer pass.
            if not focus.get("skip_discovery"):
                for cat in cats:
                    arg = {"category": cat} if cat else {}
                    disc_lines.extend(reg.dispatch("discover_symbols", arg).splitlines())
            _seen = set()
            _added = 0
            for _ln in disc_lines:
                mm = _re.match(
                    r"([^\s:]+\.(?:c|h|cc|cpp|cxx|go|java|rs)):(\d+):(.*)", _ln)
                if not mm:
                    continue
                fp, lno, content = mm.group(1), int(mm.group(2)), mm.group(3)
                fp = fp.replace("\\", "/")   # forward slashes -> valid JSON paths
                fpl = fp.lower()
                if any(n in fpl for n in _NOISE):
                    continue
                if "{%" in content or "{{" in content or "<%" in content:
                    continue                # code-generation template, not code
                head = content.split("(")[0] if "(" in content else content
                if "=" in head or ";" in content:
                    continue          # a call/declaration, not a definition
                if not fpl.endswith((".c", ".cc", ".cpp", ".cxx", ".go",
                                     ".java", ".rs")):
                    continue
                # Surface filter: drop off-surface (e.g. classical DSA/ECDSA/RSA
                # on the sig pass) unless the symbol/path is clearly PQC, so the
                # pass stops feeding the model non-PQC code it then mislabels.
                if not _surface_ok(focus, content, fpl):
                    continue
                key = (fp, lno // 60)
                if key in _seen:
                    continue
                _seen.add(key)
                body = reg.dispatch("read_file",
                                    {"path": fp, "start": max(1, lno - 5),
                                     "end": lno + 95})
                evidence_blocks.append(f"### discovered {fp}:{lno}\n{body}")
                seed_bodies.append((f"discovered {fp}", fp, body))
                _added += 1
                if _added >= 6:
                    break
        except Exception as _e:
            log.debug("discover-symbols seeding skipped: %s", _e)

        # 3. Callee expansion (open improvement #1). The analyst kept citing CALL
        # SITES (e.g. "fail = cmp(ct, cmp, sz)") as proof because it saw the
        # caller's body but never the callee's IMPLEMENTATION — so it could not
        # quote the real defect. Here we follow ONE level of calls out of every
        # seed body (entry points AND discovered functions) into security-
        # critical leaf helpers and read their bodies too. The role vocabulary is
        # focus-specific (comparison/rng/reduce for kem; hint/pack/bound for sig;
        # sample/reduce/rng for sampling) — no hardcoded names from any library.
        _ROLE_CALLEE = focus["callee_re"]
        _C_KEYWORDS = {"if", "for", "while", "switch", "sizeof", "return",
                       "do", "else", "case", "defined"}
        _callees_seen: set = set()
        _callee_added = 0
        for _lbl, _fp, _body in seed_bodies:
            if _callee_added >= 5:
                break
            for _cm in _re.finditer(r"\b([A-Za-z_]\w{2,})\s*\(", _body):
                name = _cm.group(1)
                if name in _C_KEYWORDS or name in entry_points:
                    continue
                if name in _callees_seen:
                    continue
                if not _ROLE_CALLEE.search(name):
                    continue            # not a security-critical leaf — skip
                _callees_seen.add(name)
                try:
                    cb = _best_impl(name)
                    if not cb:
                        continue
                    cfp, cln = cb
                    cfp = cfp.replace("\\", "/")   # forward slashes -> valid JSON
                    _cm = _read_enclosing_method(reg, cfp, cln, _method_line_cap)
                    if _cm:
                        cln, cbody = _cm
                    else:
                        cbody = reg.dispatch("read_file", {
                            "path": cfp, "start": max(1, cln - 5), "end": cln + 90
                        })
                    evidence_blocks.append(
                        f"### {name} (callee of {_lbl}) {cfp}:{cln}\n{cbody}")
                    _callee_added += 1
                    if _callee_added >= 5:
                        break
                except Exception:
                    continue
        if _callee_added:
            log.info("extraction: expanded %d security-critical callee(s)",
                     _callee_added)

        # 3b. Caller expansion (fail-open / result-usage detection). Many security
        # bugs live in the CALLER, not the callee: a validation/verify function
        # returns a status but the caller ignores the failure case (fail-open,
        # CWE-252/636), or dereferences a value the callee documents as nullable
        # (NPE/DoS, CWE-476). One level of DOWNWARD (callee) expansion never sees
        # this. So for each anchored security function we also pull ITS CALL SITES
        # via find_callers and read a generous window around each, so the model
        # can verify every caller enforces the negative result. Library- and
        # language-agnostic (find_callers is ripgrep-based); bounded to keep the
        # evidence budget in check. Definition lines are skipped (the body is
        # already gathered above).
        _callers_seen: set = set()
        _caller_added = 0
        _CALLER_CAP = 6
        _def_re = _re.compile(
            r"\b(?:static|public|private|protected|final|synchronized|abstract|"
            r"native|void|int|long|short|byte|boolean|char|float|double|String)\b")
        for _sym in entry_points:
            if _caller_added >= _CALLER_CAP:
                break
            try:
                callsites = reg.dispatch(
                    "find_callers",
                    {"function": _sym, "exclude": _RESOLVE_EXCLUDES})
            except Exception:
                continue
            if not callsites or callsites.startswith("["):
                continue
            for _ln in callsites.splitlines():
                mm = _re.match(
                    r"([^\s:]+\.(?:c|h|cc|cpp|cxx|go|java|rs)):(\d+):(.*)", _ln)
                if not mm:
                    continue
                cfp = mm.group(1).replace("\\", "/")
                cln = int(mm.group(2))
                content = mm.group(3)
                if any(n in cfp.lower() for n in _NOISE):
                    continue
                # Skip the DEFINITION of the symbol (a body we already have), keep
                # true call sites where the RESULT is consumed.
                if _def_re.search(content.split(_sym)[0]):
                    continue
                key = (cfp, cln // 40)
                if key in _callers_seen:
                    continue
                _callers_seen.add(key)
                try:
                    # The FULL enclosing method so EVERY exit path after the call
                    # is visible — a fail-open bug is the missing rejection on the
                    # failure branch / the silent fall-through AFTER the call site,
                    # which a fixed window routinely clips. Fixed window fallback.
                    _um = _read_enclosing_method(reg, cfp, cln, _method_line_cap)
                    if _um:
                        cln, cbody = _um
                    else:
                        cbody = reg.dispatch("read_file", {
                            "path": cfp, "start": max(1, cln - 15), "end": cln + 85
                        })
                except Exception:
                    continue
                evidence_blocks.append(
                    f"### caller of {_sym} (result-usage) {cfp}:{cln}\n{cbody}")
                _caller_added += 1
                if _caller_added >= _CALLER_CAP:
                    break
        if _caller_added:
            log.info("extraction: expanded %d caller call-site(s) for "
                     "result-usage checks", _caller_added)

        # 4. v3 stage 4: if Joern is available, auto-pull data-flow slices around
        # crypto sinks. These span multiple functions and surface bugs the
        # entry-point reads miss (the core LLMxCPG insight). Surface-neutral.
        try:
            from core.joern_slice import joern_enabled, register_joern_tool
            if joern_enabled():
                jreg = build_default_registry(context["target"], context.get("globs"))
                register_joern_tool(jreg, context["target"])
                for sink in ("division", "comparison", "rng"):
                    sl = jreg.dispatch("cpg_slice", {"sink": sink})
                    # Only real slices are added; every failure path returns the
                    # uniform "[skip]" sentinel which is filtered here so a
                    # plumbing error can never enter the model's evidence.
                    if sl and not sl.startswith("[skip]"):
                        evidence_blocks.append(f"### CPG data-flow slice ({sink})\n{sl}")
        except Exception as e:
            log.debug("joern slice gathering skipped: %s", e)

        # Java SAST: PMD + semgrep-Java are source-based (no build), so gather
        # their output deterministically here — the same way Joern slices are
        # gathered above — because the default direct-extract path never enters
        # the tool loop. Only for Java targets; appended last so the budget trim
        # drops it before the high-value entry-point bodies if space is tight.
        if (context.get("lang") or "").lower() == "java":
            try:
                from core.tools import register_java_tools
                jreg = build_default_registry(context["target"], context.get("globs"))
                register_java_tools(jreg, context["target"])
                for tool_name in ("run_pmd", "run_spotbugs"):
                    out = jreg.dispatch(tool_name, {})
                    if (out and not out.startswith("[skip]")
                            and not out.startswith("[tool")
                            and not out.startswith("[no output]")):
                        evidence_blocks.append(f"### Java SAST ({tool_name})\n{out}")
                        log.info("extraction: gathered %s output (%d chars)",
                                 tool_name, len(out))
            except Exception as e:
                log.debug("java SAST gathering skipped: %s", e)

        # Pattern-targeted slice: scan everything gathered for high-risk PQC code
        # smells and prepend a concentrated checklist, so a small local model is
        # pointed straight at the suspicious lines instead of skimming whole
        # bodies. Front-inserted so it survives the budget trim (which drops from
        # the end) and is read first.
        _risky = _risky_line_block(evidence_blocks,
                                   protocol_layer=bool(focus.get("protocol_layer")))
        _risky_count = _risky.count("\n- ") if _risky else 0
        if _risky:
            evidence_blocks.insert(0, _risky)
            log.info("extraction [%s]: flagged %d risky line(s) for scrutiny",
                     focus.get("label", "?"), _risky_count)

        # Budget priority: the trim below pops from the END, so order blocks by
        # value first. Keep the risky checklist, entry-point IMPLEMENTATIONS and
        # caller (result-usage) call-sites — the latter is where fail-open /
        # unchecked-return / null-deref bugs are visible — AHEAD of the lower-value
        # callee / discovered / SAST blocks, which are dropped first when space is
        # tight. (Previously caller blocks were appended near the end and got
        # trimmed away before the model saw them, so fail-open bugs like an OCSP
        # signature check whose false result the caller ignores were missed.)
        _hi, _lo = [], []
        for _b in evidence_blocks:
            _h0 = _b.split("\n", 1)[0]
            if ("Auto-flagged risky" in _h0 or "(implementation)" in _h0
                    or "(result-usage)" in _h0):
                _hi.append(_b)
            else:
                _lo.append(_b)
        evidence_blocks = _hi + _lo

        # Cap total evidence so prompt + reasoning + JSON output fit a ~32K
        # context. Trim PERIPHERAL blocks (callee / discovered tails are appended
        # last) from the END first; the high-value entry-point implementations are
        # gathered first and survive. Without this the KEM pass hit ~80K chars: an
        # 8B model rejected it (HTTP 400 "exceeds context size") and larger models
        # truncated their findings JSON mid-object and lost the bug. Tunable via
        # PQC_EVIDENCE_CHAR_BUDGET. (_budget is computed once up top and reused
        # here — the same value that sized the whole-method cap above.)
        _sep = 2  # len("\n\n") between blocks
        _evid_chars = sum(len(b) for b in evidence_blocks) + _sep * max(0, len(evidence_blocks) - 1)
        _trimmed = 0
        while len(evidence_blocks) > 1 and _evid_chars > _budget:
            _evid_chars -= len(evidence_blocks.pop()) + _sep
            _trimmed += 1
        if _trimmed:
            log.info("extraction [%s]: trimmed %d peripheral evidence block(s) to "
                     "fit %d-char budget", focus.get("label", "?"), _trimmed, _budget)

        evidence = "\n\n".join(evidence_blocks) or "(no code gathered)"
        log.info("extraction [%s]: %d evidence block(s), %d chars gathered; head: %s",
                 focus.get("label", "?"), len(evidence_blocks), len(evidence),
                 evidence[:140].replace(chr(10), " "))

        # Bug-class hints are language-specific: the C list (UAF, srand, memcmp)
        # misleads on a GC'd language, so swap in JAVA_PRIORS for a Java target.
        _lang = (context.get("lang") or "c").lower()
        _bug_classes = (JAVA_PRIORS + "\n\n") if _lang == "java" else (
            "Look for these PQC bug classes — but ONLY where the code shows them:\n"
            "- Non-constant-time operations on secret data (branch/memcmp/division "
            "by q in decaps)\n"
            "- Public-key validation checking only coefficient range, not "
            "canonical round-trip (CWE-680)\n"
            "- Weak/predictable RNG seeding (srand, time-based)\n"
            "- Use-after-free / double-free on error paths\n"
            "- Incorrect rejection-sampling bounds, missing FO implicit rejection\n"
            "- Missing zeroing of secret buffers\n\n"
        )
        extract_system = (
            "You are a PQC security analyst auditing a cryptographic library. "
            "Below is the ONLY code you may analyze. You have NOT seen any other "
            "code. Do not reason about functions, files, or behaviour that are "
            "not shown below.\n\n"
            "STRICT GROUNDING RULES:\n"
            "1. Report a bug ONLY if you can quote the exact vulnerable line(s) "
            "from the code below.\n"
            "2. For every finding, the 'evidence_quote' field MUST contain a "
            "verbatim line copied from the code shown. If you cannot quote it, "
            "do not report it.\n"
            "3. If the code shown does not contain a function, you CANNOT report "
            "a bug in that function. (E.g. if only ML-KEM code is shown, do NOT "
            "report ML-DSA bugs.)\n"
            "4. Prefer reporting nothing over reporting an unverifiable bug.\n"
            "5. ONLY report bugs in POST-QUANTUM CRYPTO code (ML-KEM/Kyber, "
            "ML-DSA/Dilithium, SLH-DSA, Falcon, HYBRID PQC schemes that wrap a "
            "post-quantum primitive — e.g. Ed25519-Dilithium/EdDilithium or "
            "Ed448-Dilithium — and their RNG/sampling/encoding helpers). A "
            "length / parsing / slice-bounds or reachable-panic bug on the PQC "
            "(e.g. Dilithium) portion of a hybrid Verify/Unpack IS in scope, "
            "even though the same wrapper also handles a classical half. DO NOT "
            "report bugs in TLS handshake, session export, config parsing, "
            "certificate, or general-purpose code, nor in the purely CLASSICAL "
            "half of a hybrid (e.g. the Ed25519 signature check itself) — those "
            "are out of scope for this PQC audit even if they look suspicious.\n\n"
        ) + _bug_classes + (
            "Output ONLY a JSON object, no prose, no markdown fences:\n"
            '{"findings": [{"title": "...", "cwe": "CWE-...", "file": "...", '
            '"line": <int>, "severity": "INFO|LOW|MEDIUM|HIGH|CRITICAL", '
            '"description": "...", "evidence_quote": "<verbatim line from code>", '
            '"replication": "...", "proposed_fix": "...", '
            '"evidence_refs": ["file:line"]}]}\n\n'
            "If the shown code contains no real, quotable bugs, output "
            '{"findings": []}. A finding without a verbatim evidence_quote is '
            "invalid and will be discarded."
        )
        # The PKI surface uses its own scope prompt (hunts fail-open / SSRF / DoS /
        # NPE, not constant-time / FO) instead of the PQC-restricted one above.
        if focus.get("scope") == "pki":
            extract_system = PKI_EXTRACT_SYSTEM
        # The handshake surface (boringssl-only) uses its own prompt too: the
        # generic PQC prompt above explicitly forbids reporting TLS-handshake
        # bugs (rule 5), which is correct for kem/sig/sampling but would
        # silently suppress every finding this pass exists to make.
        elif focus.get("scope") == "handshake":
            extract_system = HANDSHAKE_EXTRACT_SYSTEM
        # Generic result-usage / null-contract invariants for EVERY pass — tells
        # the model to check how the caller uses a security function's result
        # (fail-open / unchecked-null), pairing with the caller-expansion evidence.
        extract_system += RESULT_USAGE_PRIOR
        # Surface-specific emphasis: point this pass at the bug classes that live
        # on its surface so the three passes don't all re-derive the same finding.
        if focus.get("emphasis"):
            extract_system += "\n\n" + focus["emphasis"]
        # Cross-pass memory: tell this pass what earlier passes already found so it
        # stops re-deriving the same 1-2 bugs and looks for DIFFERENT ones. Empty
        # on the first/only pass, so single-pass runs are unaffected.
        # Level-B transparency (--explain): also ask the model to enumerate the
        # candidate locations it examined and DISMISSED, each with a one-line
        # reason. This is model commentary (unverified) — surfaced separately from
        # findings so a clean run can show WHY things were cleared, not just that
        # nothing was reported.
        if context.get("explain"):
            extract_system += (
                "\n\nADDITIONALLY, for transparency, add a top-level \"cleared\" "
                "array to your JSON listing candidate locations you examined and "
                "DISMISSED as not vulnerable, each with a one-line reason grounded "
                "in the code shown: "
                '{"cleared": [{"location": "file:line", "reason": "..."}]}. '
                "If you dismissed nothing, use an empty array. This is separate "
                "from findings and does not relax any finding rule."
            )
        memo = _prior_findings_memo(prior_findings or [])
        prior_block = (
            "## Already reported by earlier passes — do NOT report these again\n"
            f"{memo}\n\nReport only DIFFERENT bugs not in the list above.\n\n"
            if memo else ""
        )
        extract_user = (
            f"Library: {context['library']}\n"
            f"Target: {context['target']}\n\n"
            f"{prior_block}"
            f"## Gathered code and analysis\n\n{evidence}\n\n"
            "Now output the findings JSON with ALL bugs you can confirm"
            + (" (excluding anything already reported above)." if memo
               else ".")
        )

        try:
            # Discovery runs warm for hypothesis breadth (the reviewer filters);
            # 0.1 was too cold once temperature was honored — it collapsed the
            # investigator to one fixated finding. Tunable via config.
            raw = self.llm.complete(extract_system, extract_user, max_tokens=8192,
                                    temperature=_cfg.DISCOVERY_TEMPERATURE,
                                    format="json")
        except Exception as e:
            log.warning("extraction call failed: %s", e)
            return []

        findings = self._parse(raw, result, tool_trail)

        # Level-B: capture the model's "cleared" (examined-and-dismissed) list.
        # Unverified model commentary — stored separately from findings.
        if context.get("explain"):
            try:
                from core.llm import _extract_json
                _obj = _extract_json(raw)
                _cleared = (_obj.get("cleared") if isinstance(_obj, dict) else None) or []
                for _c in _cleared[:40]:
                    if isinstance(_c, dict) and _c.get("reason"):
                        result.triage.append({
                            "location": str(_c.get("location", "")).replace("\\", "/")[:200],
                            "reason": str(_c.get("reason", ""))[:400],
                            "pass": focus.get("label", "?"),
                        })
            except Exception as _e:
                log.debug("triage (cleared) parse skipped: %s", _e)

        # v3 anti-hallucination backstop: discard any finding whose
        # evidence_quote does not actually appear in the gathered evidence.
        # This is what stops the model inventing bugs in code it never saw
        # (e.g. claiming an ML-DSA bug while only ML-KEM code was shown).
        evidence_normalised = " ".join(evidence.split())
        target_norm = context["target"].rstrip("/")

        # IMPROVEMENT #2: location-aware grounding map. The old check only
        # verified a quote existed SOMEWHERE in the blob — so a finding could
        # quote a real line but pin it to the wrong file:line. Here we map each
        # gathered block to the source basename in its header, so we can verify
        # the quote belongs to the file the finding CLAIMS. Purely mechanical —
        # no library specifics. Block headers look like
        # "### sym (implementation) path/to/file.c:1234" or "### discovered f:ln".
        _block_by_base: dict[str, str] = {}
        for _blk in evidence_blocks:
            _hdr = _blk.split("\n", 1)[0]
            # Extension alternation ORDER matters: with nothing anchoring the
            # end of this pattern, Python re takes the FIRST alternative that
            # lets the overall match succeed, not the longest -- "c" before
            # "cc" silently truncates "foo.cc" to a captured "foo.c" (leaving
            # the trailing "c" unconsumed instead of backtracking into "cc").
            # Longer/prefix-conflicting extensions MUST come first.
            _hm = _re.search(
                r"([\w./\\-]+\.(?:cc|cpp|cxx|hpp|inc|java|go|rs|c|h))", _hdr)
            if not _hm:
                continue
            _bn = _hm.group(1).replace("\\", "/").rstrip("/").split("/")[-1].lower()
            _block_by_base.setdefault(_bn, "")
            _block_by_base[_bn] += " " + " ".join(_blk.split())
        _block_by_base = {k: v.lower() for k, v in _block_by_base.items()}
        # Files/dirs that are never valid finding locations for a library audit.
        _OUT_OF_SCOPE = ("/test", "/tests/", "test.c", "_test.", "/benchmark",
                         "/example", "/examples/", "/ide/", "/doc/", "/docs/",
                         ".md", "run_benchmark")
        # Library-AGNOSTIC PQC scope. We deliberately do NOT hardcode any single
        # library's file layout (no "asn.c"/"rsa.c" blocklist, no "allow
        # random.c" rule) -- that would let wolfSSL's structure constrain
        # liboqs / botan / circl / openssl / bouncycastle. Scope is DERIVED FROM
        # THE TARGET instead: a finding is in scope if it sits in a file the
        # investigation actually gathered PQC evidence from, OR its path names a
        # standardised PQC algorithm. Shared infra the PQC path uses (RNG, or
        # SHA-2/3 for SLH-DSA) is covered automatically because the investigator
        # reads it during the PQC hunt -- no per-library allowance needed.
        from collections import Counter as _Counter

        # (_basename is a module-level helper — shared with the orchestrator's
        # cross-pass dedupe.)

        # Files the investigator actually read / surfaced this run (basenames, so
        # a mangled absolute prefix can't defeat the match).
        gathered_basenames: set = set()
        for _c in tool_trail:
            _inp = _c.get("input", {})
            if isinstance(_inp, dict) and _inp.get("path"):
                gathered_basenames.add(_basename(str(_inp["path"])))
            # Extension order matters here too -- see the _block_by_base
            # comment above: "cc"/"cpp"/"cxx"/"hpp" must precede their
            # single-char prefixes "c"/"h" or Python re truncates the match.
            for _mm in re.finditer(
                    r"([\w./\\-]+\.(?:cc|cpp|cxx|hpp|inc|java|go|c|h))",
                    _c.get("output", "")):
                gathered_basenames.add(_basename(_mm.group(1)))

        # Also harvest basenames mentioned anywhere in the assembled evidence
        # (entry-point bodies + Joern slices) so the multi-model compare path —
        # which has no investigator tool_trail — still recognises explored files.
        for _em in re.finditer(
                r"([\w./\\-]+\.(?:cc|cpp|cxx|hpp|inc|java|go|c|h))", evidence):
            gathered_basenames.add(_basename(_em.group(1)))

        # Real source-file basenames that ACTUALLY exist in the target tree.
        # A finding whose file isn't here is a hallucinated location (e.g. the
        # model inventing /home/user/.../mldsa.c when the real file is
        # dilithium.c). Library-agnostic: derived from the target, not a list.
        from pathlib import Path as _Path
        _SRC_EXT = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".inc", ".go",
                    ".java"}
        real_basenames: set = set()
        try:
            for _rp in _Path(context["target"]).rglob("*"):
                if _rp.suffix.lower() in _SRC_EXT:
                    real_basenames.add(_rp.name.lower())
        except Exception:
            pass

        # Standardised PQC algorithm names -- identical in every library and
        # language (FIPS 203/204/205 + NIST round-4), so this list is universal,
        # not single-library bias.
        _PQC_ALGO_HINTS = (
            "mlkem", "ml_kem", "kyber", "mldsa", "ml_dsa", "dilithium",
            "falcon", "sphincs", "slhdsa", "slh_dsa", "slh-dsa", "xmss", "lms",
            "frodo", "bike", "hqc", "mceliece", "ntru", "saber",
        )

        # Spray guard: how many findings pin to each exact file:line. A single
        # line carrying many findings is the "8 generic types at one line"
        # signature -- collapsed below regardless of CWE. Target-independent.
        _loc_counts = _Counter(
            (_basename(f.file or ""), f.line)
            for f in findings if f.line is not None
        )
        _SPRAY_N = 3

        verified = []
        seen_keys: set = set()
        sprayed_seen: set = set()
        for f in findings:
            # (a) Reject findings at test/benchmark/example/doc files — these
            # are never the audit subject and signal hallucination. We do NOT
            # reject purely on an unexpected absolute prefix: local models often
            # mangle the path prefix (e.g. inventing wolfssl-5.7.0/) while still
            # naming a real source file. Instead we accept any path whose tail
            # looks like a real library source file, and reject obvious aux files.
            fp = (f.file or "").lower()
            if fp:
                if any(marker in fp for marker in _OUT_OF_SCOPE):
                    log.info("grounding: discarded test/aux-file finding '%s' "
                             "(%s)", f.title[:50], f.file)
                    if f in result.findings:
                        result.findings.remove(f)
                    continue
                # (a1) Hallucinated-location guard: the named file must
                # actually exist in the target tree. Kills invented paths and
                # filenames (e.g. /home/user/.../mldsa.c when only dilithium.c
                # exists) before any other check.
                if real_basenames and _basename(fp) not in real_basenames:
                    log.info("scope: discarded finding at non-existent file "
                             "'%s' (%s not in target tree)",
                             f.title[:50], f.file)
                    if f in result.findings:
                        result.findings.remove(f)
                    continue

                # (a2) Library-agnostic PQC scope: keep a finding only if its
                # file was actually explored this run OR its path names a PQC
                # algorithm. A finding in a file the investigator never read and
                # with no PQC marker is the model drifting off-surface -- drop it.
                # This derives scope from the target, so no single library's file
                # naming constrains another.
                in_gathered = _basename(fp) in gathered_basenames
                has_pqc_algo = any(h in fp for h in _PQC_ALGO_HINTS)
                if not in_gathered and not has_pqc_algo:
                    log.info("scope: discarded off-surface finding '%s' (%s not "
                             "in explored PQC files and no PQC algo marker)",
                             f.title[:50], f.file)
                    if f in result.findings:
                        result.findings.remove(f)
                    continue

                # Reject only if it's an absolute path that clearly belongs to a
                # DIFFERENT project (no recognizable library source structure).
                # Library-AGNOSTIC: a path is "library source" if its basename
                # actually exists in THIS target's tree, or it sits under a
                # generic source dir, or it names a standardised PQC algorithm.
                # No per-library names (wolfcrypt/, liboqs, botan, ...) are baked
                # in — those would let one library's layout gate another's run.
                looks_like_lib_src = (
                    _basename(fp) in real_basenames
                    or any(seg in fp for seg in
                           ("/src/", "/lib/", "internal/", "kem/", "sign/",
                            "/crypto/", "/pubkey/"))
                    or any(h in fp for h in _PQC_ALGO_HINTS)
                )
                if fp.startswith("/") and not looks_like_lib_src:
                    log.info("grounding: discarded out-of-scope finding '%s' "
                             "(file %s not library source)", f.title[:50], f.file)
                    if f in result.findings:
                        result.findings.remove(f)
                    continue

            # (b) De-duplicate + spray-guard (library-agnostic, open issue #2).
            #  - exact dup: same (file, line, cwe) -> keep one.
            #  - spray: when MANY findings (> _SPRAY_N) pin to the SAME file:line
            #    (the "8 generic types at one line" signature), collapse to one
            #    regardless of CWE. Two genuinely distinct bugs at one line still
            #    survive. Neither rule encodes any library's file layout.
            fp_l = fp
            if f.line is not None:
                bl = _basename(fp_l)
                exact_key = (bl, int(f.line), (f.cwe or "").lower())
                if exact_key in seen_keys:
                    log.info("dedup: dropped exact-duplicate finding '%s' "
                             "(%s:%s)", f.title[:50], f.file, f.line)
                    if f in result.findings:
                        result.findings.remove(f)
                    continue
                seen_keys.add(exact_key)
                loc_key = (bl, int(f.line))
                if _loc_counts[loc_key] > _SPRAY_N:
                    if loc_key in sprayed_seen:
                        log.info("dedup: collapsed file:line spray '%s' "
                                 "(%s:%s, %d findings at one line)",
                                 f.title[:50], f.file, f.line,
                                 _loc_counts[loc_key])
                        if f in result.findings:
                            result.findings.remove(f)
                        continue
                    sprayed_seen.add(loc_key)
            else:
                title_key = (f.title.strip().lower(), _basename(fp_l))
                if title_key in seen_keys:
                    log.info("dedup: dropped duplicate finding '%s' (%s)",
                             f.title[:50], f.file)
                    if f in result.findings:
                        result.findings.remove(f)
                    continue
                seen_keys.add(title_key)

            # (b2) Title-claim consistency: if the TITLE names a specific code
            # symbol (a call like 'srand(' or a `backticked` identifier) that is
            # NOT present in the gathered code, the finding references code it
            # never saw (the 'claims srand, but random.c has no srand' false
            # positive). Drop it before it can ever be 'confirmed'.
            # NOTE: the call pattern requires the '(' IMMEDIATELY after the name
            # (no whitespace) so a PROSE title like "no scheme restriction (SSRF)"
            # is not misread as a call to `restriction(` and wrongly discarded —
            # real code claims are written `srand(`, never `srand (`.
            _ev_low = evidence_normalised.lower()
            _title_syms = set(re.findall(r"`([A-Za-z_]\w{2,})`", f.title))
            _title_syms |= set(re.findall(r"\b([A-Za-z_]\w{2,})\(", f.title))
            _missing = [s for s in _title_syms if s.lower() not in _ev_low]
            if _title_syms and _missing:
                log.info("grounding: discarded finding '%s' - title names %s "
                         "absent from gathered code (claim/code mismatch)",
                         f.title[:50], _missing)
                if f in result.findings:
                    result.findings.remove(f)
                continue

            # (c) Quote grounding check.
            quote = ""
            for ev in f.evidence:
                # The quote is stored as "[evidence_quote] <text>". Strip ONLY the
                # bracket tag — do NOT split on ':' (a C line with a ternary,
                # `case x:`, or a label would be truncated, corrupting the probe
                # and dropping a real finding). The bare "evidence_quote:" form is
                # a legacy fallback that the parser never actually emits.
                if ev.startswith("[evidence_quote]"):
                    quote = ev.split("]", 1)[-1].strip()
                    break
                if ev.startswith("evidence_quote:"):
                    quote = ev.split(":", 1)[-1].strip()
                    break
            if not quote:
                f.add_evidence("grounding", "no evidence_quote provided — unverified")
                f.confidence = Confidence.SUSPECTED
                verified.append(f)
                continue
            q_norm = " ".join(quote.split()).lower()
            ev_lower = evidence_normalised.lower()
            probe = q_norm[:15]
            if not (probe and probe in ev_lower):
                log.info("grounding: discarded unverifiable finding '%s' "
                         "(quote not found in gathered code)", f.title[:60])
                if f in result.findings:
                    result.findings.remove(f)
                continue
            # IMPROVEMENT #2: location-aware check. The quote exists in the
            # evidence — but does it exist in the file this finding CLAIMS? If we
            # gathered a block for the claimed file and the quote is NOT in it
            # (yet appears elsewhere), the finding pinned the wrong location.
            # Demote to SUSPECTED + annotate rather than hard-drop, so a real bug
            # cited at a slightly-off line still survives for the reviewer.
            claimed_base = _basename(f.file or "")
            if claimed_base and claimed_base in _block_by_base:
                if probe not in _block_by_base[claimed_base]:
                    log.info("grounding: finding '%s' quote not in claimed file "
                             "%s (found elsewhere) — demoting, location suspect",
                             f.title[:50], f.file)
                    f.add_evidence("grounding",
                                   f"location suspect: evidence_quote not found in "
                                   f"{claimed_base}; verify the cited file:line")
                    f.confidence = Confidence.SUSPECTED
            verified.append(f)

        log.info("grounding: %d/%d findings verified against gathered code",
                 len(verified), len(findings))

        # Level-A: record what this pass examined onto the result (deterministic
        # coverage). Guarded — transparency must never break a discovery pass.
        try:
            cov = result.coverage
            eps_map = cov.setdefault("entry_points", {})
            for _ep, _info in _ep_cov.items():
                # Keep a resolved record if ANY pass resolved the symbol.
                if _ep not in eps_map or (
                        _info.get("resolved") and not eps_map[_ep].get("resolved")):
                    eps_map[_ep] = _info
            cov.setdefault("passes", []).append({
                "label": focus.get("label", "?"),
                "scope": focus.get("scope"),
                "risky_lines": _risky_count,
                "evidence_blocks": len(evidence_blocks),
                "evidence_chars": len(evidence),
                "grounded": len(verified),
            })
        except Exception as _e:
            log.debug("coverage record skipped: %s", _e)

        return verified

    def _parse(self, raw_text: str, result: AssessmentResult,
               tool_trail: list[dict]) -> list[Finding]:
        """Extract findings from the model output.

        Three extraction strategies in priority order:
          1. Final JSON block  {"findings": [...]}  — ideal case
          2. Inline <finding>{...}</finding> tags   — incremental emission
          3. Nothing found                          — warn and return []

        Using both means we get findings even when the model runs out of turns
        mid-investigation, as long as it emitted at least one <finding> tag.
        Deduplication by title prevents double-counting when both are present.
        """
        trail = "\n".join(
            f"- {c['name']}({_fmt(c['input'])}) -> {c['output'][:300]}"
            for c in tool_trail
        ) or "(no tool calls — reason mode)"

        items: list[dict] = []

        # Strategy 1: final JSON block
        from core.llm import _extract_json
        data = None
        try:
            data = _extract_json(raw_text)
            if isinstance(data, dict):
                # Accept several wrapper keys models commonly emit, not just
                # "findings" (qwen3-coder often uses "bugs"/"vulnerabilities").
                for key in ("findings", "bugs", "vulnerabilities", "issues",
                            "results"):
                    if data.get(key):
                        items = data[key]
                        log.debug("parsed %d finding(s) from JSON key '%s'",
                                  len(items), key)
                        break
            elif isinstance(data, list) and data:
                # Bare array of finding objects
                items = data
                log.debug("parsed %d finding(s) from bare JSON array", len(items))
        except Exception:
            pass

        # Strategy 2: inline <finding> tags (fallback / supplement)
        tag_items = []
        for m in _FINDING_TAG_RE.finditer(raw_text):
            try:
                tag_items.append(json.loads(m.group(1)))
            except json.JSONDecodeError:
                pass
        if tag_items:
            log.debug("found %d inline <finding> tag(s)", len(tag_items))

        # Merge: prefer final JSON block but fill in any tagged findings not
        # already present (match by title). Guard against non-dict items the
        # model sometimes mixes into the array.
        items = [it for it in items if isinstance(it, dict)]
        existing_titles = {it.get("title", "").lower() for it in items}
        for ti in tag_items:
            if ti.get("title", "").lower() not in existing_titles:
                items.append(ti)
                existing_titles.add(ti.get("title", "").lower())

        if not items:
            # De-conflate three very different "no findings" causes so run logs
            # are trustworthy: (a) the model cleanly reported nothing, (b) its
            # output was TRUNCATED mid-object so a real finding was lost, (c) an
            # unrecognised format. (a) is normal; (b) means raise num_predict.
            _stripped = raw_text.strip()
            _began = '"title"' in raw_text or '"cwe"' in raw_text
            _closed = _stripped.endswith("}") or _stripped.endswith("]")
            _wrapper_keys = ("findings", "bugs", "vulnerabilities", "issues",
                             "results")
            if (isinstance(data, dict) and any(k in data for k in _wrapper_keys)) \
                    or (isinstance(data, list) and not data):
                log.info("investigator reported no findings (clean empty result)")
            elif _began and not _closed:
                log.warning(
                    "investigator output TRUNCATED at %d chars — a finding was "
                    "likely lost; raise extraction num_predict. Output ended: …%s",
                    len(raw_text), _stripped[-160:].replace("\n", " "),
                )
            else:
                log.warning(
                    "could not parse investigator findings (unrecognised format) "
                    "— output started: %s", raw_text[:200].replace("\n", " "),
                )
            return []

        out = []
        skipped = 0
        if items:
            log.info("_parse: processing %d item(s); first item keys=%s",
                     len(items), list(items[0].keys()) if isinstance(items[0], dict) else type(items[0]).__name__)
        for it in items:
            if not isinstance(it, dict):
                skipped += 1
                continue
            # Accept many alternate title keys models emit.
            title = (it.get("title") or it.get("name") or it.get("summary")
                     or it.get("id") or it.get("vulnerability")
                     or it.get("issue") or it.get("bug") or it.get("type")
                     or it.get("cwe") or "").strip()
            if not title:
                # Last resort: use the description's first sentence as title.
                desc = str(it.get("description") or it.get("detail") or "")
                if desc:
                    title = desc.split(".")[0][:80].strip()
            if not title:
                skipped += 1
                log.info("_parse: skipped item with no usable title; keys=%s",
                         list(it.keys()))
                continue
            it["title"] = title  # normalise for downstream use
            try:
                sev = Severity.from_str(it.get("severity", "MEDIUM"))
            except (KeyError, ValueError):
                sev = Severity.MEDIUM
            # Coerce line to int if the model returned a string/None.
            line_val = it.get("line")
            file_val = it.get("file")
            # Many models emit a combined "location": "file.c:1234" field instead
            # of separate file/line. Split it so the reviewer can read the code.
            if (not file_val or not line_val) and it.get("location"):
                import re as _re
                loc = str(it["location"])
                m = _re.search(r"([^\s:]+\.(?:c|h|cc|cpp|go|java|inc))[:\s]+(\d+)", loc)
                if m:
                    file_val = file_val or m.group(1)
                    line_val = line_val or m.group(2)
                elif not file_val:
                    file_val = loc  # at least record the raw location
            if isinstance(line_val, str):
                import re as _re
                m = _re.search(r"\d+", line_val)
                line_val = int(m.group()) if m else None
            elif not isinstance(line_val, int):
                line_val = None
            f = Finding(
                title=title,
                phase=Phase.STATIC,
                severity=sev,
                confidence=Confidence.SUSPECTED,
                description=it.get("description", ""),
                file=file_val,
                line=line_val,
                entry_point=it.get("entry_point"),
                cwe=it.get("cwe"),
                spec_reference=it.get("spec_reference"),
                matched_target=None,
            )
            if it.get("evidence_quote"):
                f.add_evidence("evidence_quote", str(it["evidence_quote"]))
            if it.get("replication"):
                f.add_evidence("replication", it["replication"])
            if it.get("proposed_fix"):
                f.add_evidence("proposed_fix", it["proposed_fix"])
            if it.get("evidence_refs"):
                f.add_evidence("investigator_cited", str(it["evidence_refs"]))
            f.add_evidence("tool_trail", trail)
            out.append(result.add(f))
        if skipped:
            log.info("_parse: built %d finding(s), skipped %d (missing title/bad shape)",
                     len(out), skipped)
        return out


def _fmt(d: dict) -> str:
    return ", ".join(f"{k}={v}" for k, v in d.items())


def _basename(p: str) -> str:
    """Lower-cased file basename, slash-normalised. Shared by the grounding
    checks and the multi-pass cross-pass dedupe so a mangled path prefix can't
    defeat either match."""
    return (p or "").replace("\\", "/").rstrip("/").split("/")[-1].lower()


# High-risk PQC code smells. Deterministic, high-precision-ish patterns that map
# to the bug classes this assessor cares about. Surfaced as a checklist so a small
# local model doesn't skim past the one risky line in a 95-line function body.
_RISKY_PATTERNS = [
    (re.compile(r"\b(?:memcmp|XMEMCMP|CRYPTO_memcmp)\s*\("),
     "variable-time compare — must be constant-time on secret/ciphertext (CWE-208)"),
    (re.compile(r"\b(?:memcpy|XMEMCPY|memmove|XMEMMOVE)\s*\([^;]*,[^;,]*"
                r"(?:\+|\*|<<|\blen\b|\bsize\b|\[)"),
     "copy with a computed/input-derived length — overflow risk (CWE-787/120)"),
    (re.compile(r"[)\]\w]\s*[/%]\s*[A-Za-z_]\w*"),
     "division/modulo by a variable — timing leak if the operand is secret "
     "(KyberSlash, CWE-385)"),
    (re.compile(r"\b(?:if|while|for|return)\b[^;{}]*"
                r"\b(?:secret|sk|priv|coins|rho|sigma|noise|prf|seed|nonce)\w*"),
     "control flow uses a secret-named value — secret-dependent branch"),
    # --- Java-specific PQC anti-patterns (the C idioms above never fire on
    # .java files). The risky-line block is a "scrutinise these" checklist, so
    # mild over-flagging is acceptable; the model verifies against the body.
    (re.compile(r"\bArrays\.equals\s*\("),
     "Java variable-time array compare (Arrays.equals) — use "
     "MessageDigest.isEqual / Arrays.constantTimeAreEqual on secrets (CWE-208)"),
    (re.compile(r"\bnew\s+Random\s*\(|\bMath\.random\s*\(|\bjava\.util\.Random\b"),
     "weak/predictable RNG (java.util.Random / Math.random) — key/nonce "
     "material needs SecureRandom (CWE-330/338)"),
    (re.compile(r"\.setSeed\s*\(|\bnew\s+SecureRandom\s*\(\s*[\w\[\]\"']"),
     "seeded SecureRandom / setSeed — predictable if the seed is fixed or "
     "derived (CWE-336)"),
    (re.compile(r"\bnew\s+BigInteger\b"),
     "BigInteger arithmetic is variable-time — timing leak if it processes "
     "secret/key material (CWE-208)"),
]

# RFC 8446 handshake-state-machine code smells. Unlike _RISKY_PATTERNS above
# (which flags a risky OPERATION), a missing CH1/CH2 consistency check is an
# ABSENCE, not an operation -- so instead of pattern-matching the bug itself,
# this flags every occurrence of the specific RFC 8446 fields/state that MUST
# be checked across ClientHello1/ClientHello2 or HelloRetryRequest (§4.1.2,
# 4.1.4, 4.2.8, 4.4.1 -- see prompts.pqc_researcher._HANDSHAKE_PRIORS), so the
# model is pointed at every line touching them and has to judge presence/
# absence of the required comparison itself. Only merged in for protocol_layer
# focuses (handshake / ch_consistency, boringssl-only) -- these are BoringSSL
# identifier names (ssl/*.cc) and would just add noise to the crypto-primitive
# passes for every other library.
_HANDSHAKE_RISKY_PATTERNS = [
    (re.compile(r"\bsupported_groups\b"),
     "RFC 8446 §4.1.2 CH1/CH2 consistency field — confirm CH2's value is "
     "compared against CH1's, not just read or overwritten"),
    (re.compile(r"\bcipher_suites?\b"),
     "RFC 8446 §4.1.2 CH1/CH2 consistency field — confirm CH2's value is "
     "compared against CH1's, not just read or overwritten"),
    (re.compile(r"\bcompression_methods?\b"),
     "RFC 8446 §4.1.2 CH1/CH2 consistency field — confirm CH2's value is "
     "compared against CH1's, not just read or overwritten"),
    (re.compile(r"\bsession_id\b"),
     "RFC 8446 §4.1.2 CH1/CH2 consistency field — confirm CH2's value is "
     "compared against CH1's, not just read or overwritten"),
    (re.compile(r"\breceived_hello_retry_request\b"),
     "HRR-replay guard state (RFC 8446 §4.1.4) — confirm a SECOND HRR is "
     "structurally rejected, not merely assumed impossible"),
    (re.compile(r"\bkey_share\w*\b.*\b(?:count|duplicate|entries)\b",
                re.IGNORECASE),
     "duplicate KeyShareEntry check (RFC 8446 §4.2.8) — confirm the selected "
     "group can't appear twice"),
    (re.compile(r"\bmessage_hash\b"),
     "HRR synthetic transcript record (RFC 8446 §4.4.1) — confirm this fires "
     "exactly once, not skipped or doubled"),
    (re.compile(r"\bpsk_identit(?:y|ies)\b|\bbinder\b"),
     "PSK binder/identity re-lookup across CH1→CH2 (RFC 8446 §4.1.4) — "
     "confirm re-lookup is by identity VALUE, not a stored index"),
]


def _risky_line_block(evidence_blocks: list, cap: int = 12,
                      protocol_layer: bool = False) -> str:
    """Scan already-gathered code blocks for high-risk PQC patterns and return a
    concentrated 'auto-flagged lines' checklist (or '' if none). Each block is
    '### <header with path:line>\\n<body whose lines are 'NNN: code'>'. Comment
    lines are skipped for the crypto-primitive patterns (so memcmp/div/etc
    mentioned in prose don't fire) but NOT for the handshake patterns -- a
    missing-consistency-check bug is an absence, not an operation, and
    developer comments explaining an intentional negotiation shortcut are
    exactly where this bug class tends to self-document."""
    hits: list[tuple[str, str, str]] = []
    seen: set = set()
    for block in evidence_blocks:
        lines = block.splitlines()
        if not lines:
            continue
        hm = re.search(r"([^\s()]+\.(?:c|h|cc|cpp|cxx|hpp|inc|go|java|rs)):\d+", lines[0])
        base = _basename(hm.group(1)) if hm else "?"
        for raw in lines[1:]:
            m = re.match(r"\s*(\d+):(.*)$", raw)
            lineno, code = (m.group(1), m.group(2)) if m else ("", raw)
            s = code.strip()
            if not s:
                continue
            is_comment = s.startswith(("*", "//", "/*", "*/", "#"))
            patterns = list(_HANDSHAKE_RISKY_PATTERNS) if protocol_layer else []
            if not is_comment:
                patterns = _RISKY_PATTERNS + patterns
            for rx, why in patterns:
                if rx.search(s):
                    loc = f"{base}:{lineno}" if lineno else base
                    key = (loc, why)
                    if key in seen:
                        break
                    seen.add(key)
                    hits.append((loc, s[:160], why))
                    break
            if len(hits) >= cap:
                break
        if len(hits) >= cap:
            break
    if not hits:
        return ""
    out = ["### Auto-flagged risky lines — scrutinise these specifically (some may "
           "be false alarms; verify against the full code below)"]
    for loc, code, why in hits:
        out.append(f"- `{loc}`  — {why}\n    {code}")
    return "\n".join(out)


def _surface_ok(focus: dict, content: str, path: str) -> bool:
    """False if a discovered symbol is OFF this focus's crypto surface (e.g.
    classical DSA/ECDSA/RSA on the sig pass). The focus's 'surface_keep' tokens
    (post-quantum) override 'surface_drop' tokens, so wc_MlDsaKey_* / slh_dsa_*
    survive even though they contain the 'dsa' substring. Focuses without a
    'surface_drop' accept everything (unchanged behaviour)."""
    drop = focus.get("surface_drop")
    if not drop:
        return True
    txt = (content + " " + path).lower()
    if any(k in txt for k in (focus.get("surface_keep") or ())):
        return True
    return not any(d in txt for d in drop)


def _prior_findings_memo(findings: list, cap: int = 15, char_cap: int = 1600) -> str:
    """Compact one-line-per-finding list of what EARLIER passes already reported,
    so the next pass can be told to avoid re-deriving them and hunt for DIFFERENT
    bugs (the breadth lever — passes otherwise fixate on the same 1-2 findings).

    Returns '' when there is nothing prior, so single-pass runs are unaffected."""
    if not findings:
        return ""
    lines = []
    for f in findings[:cap]:
        loc = (f"{_basename(f.file or '')}:{f.line}" if f.line is not None
               else _basename(f.file or "") or "?")
        sev = getattr(f.severity, "name", str(f.severity))
        cwe = (f.cwe or "").strip()
        lines.append(f"- [{sev}] {f.title.strip()} ({loc}"
                     f"{', ' + cwe if cwe else ''})")
    memo = "\n".join(lines)
    if len(memo) > char_cap:
        memo = memo[:char_cap].rsplit("\n", 1)[0]
    return memo
