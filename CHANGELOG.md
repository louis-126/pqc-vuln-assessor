# Changelog

All notable changes to this project. Newest first.

### 2026-07-22 — web frontend, run manifests, tooling ergonomics

**Web UI (`web/`, new).** Optional Flask frontend over the CLI — it shells out to
`main.py`, so every web scan produces the same `runs/<lib>/<ts>/` artifacts.
- Submit a scan from a **GitHub URL** (shallow-cloned to `web/workspaces/`) or a
  **local folder** (zero-copy; the path field is a filepath drop target).
- **Library auto-detection** by grepping each library's own entry-point symbols.
- Options mirror the CLI: mode, backend, model, `--explain`, and
  `PQC_DISCOVERY_PASSES` (kem/sig/sampling/pki/all).
- **Anthropic key is read from the environment** (`ANTHROPIC_API_KEY`), never
  entered in or sent through the browser; the UI only reports whether it is set.
- Live progress tails `run.log`, **Cancel** sends SIGINT (partial report), and a
  finished scan **redirects to the result**.
- **Scan history** with per-scan delete and **Clear all runs & clones** (prunes
  `web/workspaces/`). Result viewer renders severity summary, Scope & Coverage,
  and findings.
- **Library editor** (`/libraries`) — view/edit/create/delete `libraries/*.toml`
  in the browser; saves are validated like the scanner loads them and
  hot-reloaded via `config.reload_libraries()`.
- **Made hard to misuse** — the library dropdown starts blank until detected/
  chosen; every option has an ⓘ tip and a live plain-English description; a
  "how a scan works" panel onboards newcomers.

**CLI run records.** Each run now writes a `run.log` (full console log) and a
`run.json` manifest (command, target git commit, backend/model, per-stage
timings, token usage); `report.json` gained `duration_seconds`; the live display
prints a per-section timing breakdown; `runs/<lib>/latest` symlinks the newest.

**Ergonomics.** `--doctor` prints per-language tool availability and exits;
off-language SAST warnings (Go/Java on a C/C++ target) are silenced; Ctrl-C
writes a partial report instead of a traceback.

**Library config.** Per-library data moved to one self-contained
`libraries/<name>.toml` each (validated at load); expanded/verified entry points
for botan (full PQC surface), openssl (native FIPS 203/204/205), and circl.

**Packaging.** `requirements.txt` now also carries Flask for the web UI;
`.gitignore` covers the in-root virtualenv and `web/workspaces/`.


### 2026-07 — run transparency: Scope & Coverage, entry-point disposition, `--explain`

**The gap.** A 0-finding report rendered a blank *"No findings."* page — a run
that analysed hardened code and correctly found nothing looked identical to a run
that never really executed. There was also no visibility into whether each curated
entry point actually resolved to real code in the target.

**The additions** (all guarded so transparency can never break a report or a
discovery pass):
- **Scope & Coverage** section on every report — cryptographic surfaces examined,
  a **per-entry-point disposition table** (`examined — cleared` / `flagged` /
  `symbol not found in target`), per-pass risky-line counts, and an explicit
  true-negative statement for clean runs.
- **`--explain`** adds a **Triage Log** — the candidates the investigator examined
  and *dismissed*, each with a one-line reason. Labelled unverified model
  commentary, not a grounded verdict.
- `AssessmentResult` now carries `coverage` + `triage`, serialised into
  `report.json`. New run artefacts `run.log` and `run.json` (manifest) land beside
  the report, and `runs/<lib>/latest` symlinks the newest auto-named run.
- Earlier in the same line of work: graceful Ctrl-C (writes a partial report,
  exit 130) and a `--doctor` tool-availability preflight.

The entry-point disposition table immediately surfaced three Botan entry points
that were silently resolving to the wrong code (a TLS shim, the generic
compression module, and the HSS/LMS algorithm); all were repointed to the correct
ML-KEM/ML-DSA symbols.

### 2026-07 — reviewer PKI scope (provider-layer findings no longer demoted as out-of-scope)

**The gap.** Discovery was extended to the PKI/provider surface, but the reviewer
was not — it still grounded every verdict in a FIPS 203/204/205 crypto clause. So
in `agent-review` it disputed/demoted LIB-01…04 as *"outside the ML-KEM/ML-DSA
scope"* and, mechanically, auto-demoted any `confirmed` PKI finding to
needs-evidence because it lacked a FIPS `spec_clause`. Net: `agent-review`
reported 0 confirmed on real provider-layer bugs.

**The fix** (generic — keyed off discovery surface + CWE, no library file names):
- `PKI_REVIEWER_SYSTEM` — a review prompt scoped to the provider-layer bug
  classes (fail-open CWE-347/636/392/295, NPE CWE-476, SSRF CWE-918, unbounded
  CWE-400/770, config CWE-15). It judges findings on their **CWE merits** and
  explicitly forbids disputing one merely for "not being ML-KEM/ML-DSA".
- `_is_pki_finding()` routes a finding to the PKI reviewer when it came from the
  `pki` surface (the `discovery_pass` tag) **or** carries a plumbing CWE with no
  PQC algorithm named. A genuine ML-DSA signature finding (also CWE-347) stays on
  the crypto reviewer via the `has_algo` guard.
- The confirmation gate is branched: PKI findings ground on their **CWE** instead
  of a FIPS clause and skip the crypto operation-consistency check; the crypto
  path is unchanged. `_packet` feeds a CWE scope note in place of the (empty) FIPS
  excerpt.

Effect: on the `pki` surface, `agent-review` now confirms LIB-01…04 on their own
merits instead of stamping them out-of-scope. The crypto reviewer
(`kem`/`sig`/`sampling`) is untouched.

### 2026-07 — deeper evidence: full-method extraction, multi-pass PKI, fail-open priors

**Full-method (brace-matched) evidence** — the biggest lever for control-/data-flow bugs
- `agents.researcher._read_enclosing_method` returns the *whole* enclosing method
  around each anchor (entry-point bodies, callee and caller expansion) instead of
  a fixed line window. A fail-open needs EVERY exit path in frame (a swallowed
  exception or a silent fall-through), and a null-deref needs the call site and
  the (absent) guard together — a window clips exactly these. Walks brace nesting
  (handles multi-line signatures, nested if/try blocks); generic to brace
  languages; falls back to a fixed window for oversized methods or non-brace src.
- Reads the file directly (not via `reg.dispatch`, whose 6000-char output cap
  truncated a several-hundred-line window and dropped the anchor). Verified: the
  BouncyCastle OCSP `check()` method (168 lines) is now captured whole — which
  surfaced the LIB-01 fail-open (`ProvOcspRevocationChecker:264`, CWE-347) for
  the first time.
- The whole-method size cap is **budget-derived but ceilinged at 400 lines** —
  `min(400, budget//3//50)`. Empirically, letting a big-context backend inline
  very large methods (a 445-line `engineValidate` + a 168-line `check()` + …)
  ballooned the evidence to the 150K ceiling, forced trimming, and DROWNED the
  signal: findings fell 11→6 and the LIB-01 fail-open was lost. ~400 lines is the
  sweet spot — a mid-size decisive method (`check()`, 168) inlines whole while
  oversized glue (`engineValidate`, 445) stays a window and the budget doesn't
  overflow. The budget-derived floor still scales DOWN for small local budgets
  (Ollama ~48K → ~320), so it stays generic with no per-library number. The read
  window scales with the cap so an in-range method's closing brace is never
  clipped.
- **Result — full LIB-01…04 sweep in one run** (Anthropic, `PQC_DISCOVERY_PASSES=pki`,
  8 findings, no trimming, 136K tokens): LIB-01 fail-open (`ProvOcspRevocationChecker`,
  CWE-347), **LIB-02 for the first time** (`X509RevocationChecker:380`, CWE-476 —
  the model cited the exact conditional-null contract: *"getTrustedCert() returns
  null … when the anchor was constructed with a CA name + public key instead of a
  certificate"*, i.e. the `RESULT_USAGE_PRIOR` conditional-null pattern firing),
  LIB-03 (CRL SSRF + LDAP/JNDI + no size cap), and LIB-04 (PKCS#12 iteration cap).
  LIB-02 surfaced from the compact `X509RevocationChecker.check` (fits the 400
  cap whole), not the 445-line `engineValidate` — lean evidence + the prior, not
  a giant inlined method, is what found it.

**Fail-open / conditional-null priors** (generic, no library API names)
- `RESULT_USAGE_PRIOR` gains two CWE patterns applied to every pass: void-validator
  fail-open (CWE-636/392 — walk every exit path; the *absence* of a throw on an
  error branch is the bug) and conditional-null (CWE-476 — a value null only for a
  rare, attacker-selectable form is still a dereference bug).

**Multi-pass PKI + variant coverage**
- The `pki` focus runs `repeat: 3` passes with cross-pass memory ("already
  reported X — find DIFFERENT bugs") to beat single-call fixation.
- `_best_impls` gathers the top hit plus same-basename sibling variants (e.g.
  `prov` vs `pkix` `CrlCache.java`), ending the run-to-run "which variant did we
  happen to read" coverage gap — bounded so an unrelated same-named class is never
  pulled in.

**Resolution de-truncation & grounding**
- `search_code` / `find_callers` accept `exclude` globs; symbol resolution now
  skips test/example/generated/multi-release files that otherwise filled the
  output cap and truncated the real definition (`checkCertificate` went from
  unresolved to the real `PKIXCertPathValidatorSpi`).
- Title-claim grounding requires an identifier immediately followed by `(` before
  treating a word as a code claim, so a valid finding is no longer discarded over
  an ordinary English word in its title.

**Backend-aware evidence budget**
- `config.backend_evidence_budget()` defaults to 150K chars for Anthropic
  (big-context) vs 48K for local Ollama models; `PQC_EVIDENCE_CHAR_BUDGET` still
  overrides. Threaded through via the `backend` context key.

### 2026-07 — Windows support, Java targets, Anthropic backend, PKI surface

**Windows portability** (the researcher pipeline now runs correctly on native Windows)
- Resolve the target to an absolute path in `build_default_registry` — a relative
  `--target` (e.g. `..\bc-java`) previously made `read_file` do
  `absolute.relative_to(relative)`, raising `ValueError` and aborting the whole
  evidence gather (0 blocks, 0 findings).
- JSON repair for Windows paths (`core.llm._extract_json`) — the model copies
  paths like `.\core\src\...` into the findings JSON, where `\c`/`\s`/`\b` are
  invalid escapes that broke `json.loads` and silently dropped real findings.
  Lone backslashes are now doubled, and evidence paths are normalized to forward
  slashes at the source (which also fixes noise filters like `/jdk1.` on Windows).
- UTF-8 subprocess decoding (`_run` / `_go_run` / `discover_symbols` / `base.sh`)
  — Windows' cp1252 default crashed a reader thread on non-cp1252 tool output.
- Note: requires a real `rg.exe` on PATH (a shell-function ripgrep is invisible to
  `shutil.which`).

**Java target support**
- Java risky-line patterns (`Arrays.equals`, `java.util.Random`/`Math.random`,
  seeded `SecureRandom`, `BigInteger`) and the risky-line header regex now cover
  `.java`; `JAVA_PRIORS` swaps the C bug-class list (UAF/srand) for Java-relevant
  ones with GC- and exception-as-validation semantics.
- Java SAST tools (`register_java_tools`): PMD (source-based, no build) and
  SpotBugs+FindSecBugs (bytecode — point `FINDSECBUGS_PLUGIN` at the jar),
  gathered deterministically into the evidence. Both Windows-native; semgrep is
  not used (no native Windows build).
- SLH-DSA / FIPS 205: BouncyCastle entry points, reviewer spec mapping, and
  requirement text.

**Anthropic backend (`--backend anthropic`)**
- Drop the deprecated `temperature` parameter — Opus 4.8 / Sonnet 4.x return
  HTTP 400 "temperature is deprecated for this model"; `LLMConfig.send_temperature`
  (default off) gates it.
- Surface real API errors — `_post` no longer hides the 400 body behind a bare
  "Bad Request" or retries non-retryable 4xx.

**PKI / provider discovery surface** (opt-in: `PQC_DISCOVERY_PASSES=pki`)
- New `pki` focus that hunts the *non-crypto* bug classes — fail-open
  verification, NPE/DoS, SSRF, resource-exhaustion — in certificate-path
  validation, revocation (OCSP/CRL) and keystore loading. Anchors on
  `config.PKI_ENTRY_POINTS`, skips the PQC-only `discover_symbols` seeding, and
  uses a dedicated `PKI_EXTRACT_SYSTEM` prompt. Rediscovers the BouncyCastle
  LIB-03 (CRLDP SSRF + unbounded) and LIB-04 (PKCS#12 iteration cap) findings.
- Caller (upward) expansion — for each anchored security function, `find_callers`
  gathers its call sites so fail-open / unchecked-return bugs (which live in the
  *caller*, invisible to one-level callee expansion) are shown. Library- and
  language-agnostic (ripgrep-based), bounded.
- `RESULT_USAGE_PRIOR` on every extraction prompt — generic secure-coding
  invariants (enforce failure results, guard nullable returns) that pair with the
  caller evidence to catch fail-open (CWE-252/636) and null-deref (CWE-476) bugs.

### 2026-07 — discovery quality, trustworthy review, and a PoC testbed

**Discovery**
- Multi-pass evidence budget (`config.evidence_char_budget()`) so a huge pass no
  longer 400s an 8B model or truncates its findings JSON; parse logging now
  distinguishes truncated vs clean-empty vs unparseable.
- Semantic near-duplicate dedup across passes (`core/finding_similarity.py`).
- Cross-pass memory — each pass is told what earlier passes found and hunts for
  *different* bugs.
- Sig-pass surface filter — drops classical DSA/ECDSA/RSA, keeps ML-DSA/SLH-DSA
  (stops the "classical DSA mislabelled ML-DSA" confabulation).
- Pattern-targeted risky-line slices — prepends a checklist of non-constant-time
  compares, variable-time division (KyberSlash), secret-dependent branches and
  computed-length copies so a small local model is pointed at the needle.

**Review & resolution**
- Per-finding review (one model call per finding) — eliminates cross-finding
  verdict scrambling; truncation-safe (a truncated review can never *dispute* a
  real finding). Pass `--reviewer-model` for an independent second model.
- Resolution follows call-site-only proofs into the callee's body.

**PoC generation**
- CodeAct compile-and-fix loop (`--poc-compile-rounds N`): drafts C, compiles it
  (`clang -fsyntax-only`), feeds real compiler errors back to fix it.
- Optional Claude drafter (`--poc-drafter-model claude-sonnet-4-6`) for
  compile-ready C; discovery/review stay local.
- wolfSSL PoCs are **client-only attacker clients** against a shared, sanitized
  ML-KEM victim server — so a PoC can never self-grade.

**PoC testbed (`tools/`)**
- Generic runner (`run_poc.sh`) + batch mode (`run_pocs.py`): build, run, and
  classify on **independent detectors only** (a real sanitizer report or crash
  signal), never on a string the PoC prints about itself.
- Shared ML-KEM client/server template (`tools/template/`) + per-library build
  notes (`tools/LIBRARY_BUILD_NOTES.md`). See `POC_TESTBED_HANDOVER.md`.
