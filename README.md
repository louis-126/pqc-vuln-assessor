# PQC Vulnerability Assessor

Multi-agent system that security-assesses post-quantum cryptography
implementations (ML-KEM / ML-DSA / SLH-DSA) and emits disclosure-ready reports.
Runs on **local Ollama models by default** — no API key, no source leaves the
machine — with a dormant Anthropic backend available behind `--backend anthropic`.
Curated entry points ship for **boringssl, botan, bouncycastle, circl, liboqs,
openssl, and wolfssl**; any other library name runs discovery-only (symbol
enumeration drives the hunt, no code change needed). Each curated library is one
self-contained `libraries/<name>.toml` (source language + crypto/PKI entry
points) — add a library by dropping in a new TOML file, no code edit required. Built from the Team 14
handover; validated against three manually-found wolfSSL 5.9.1 issues (WF-001,
WF-004, CVE-2026-5460).

## Start here

New to the project? Read the docs in this order:

1. **This README** — what the tool is and a 30-second quick start (below).
2. **[STRUCTURE.md](STRUCTURE.md)** — **Directory & Codebase Map** (start here to understand the files and folders).
3. **[TEAM_GUIDE.md](docs/TEAM_GUIDE.md)** — the canonical setup → run → read-the-report walkthrough. Start here for a full install.
4. **[MODES.md](docs/MODES.md)** — what each `--mode` does and when to use it.

Reference / deeper docs live in [`docs/`](docs/) and [`tools/`](tools/):
- [`docs/POC_TESTBED_HANDOVER.md`](docs/POC_TESTBED_HANDOVER.md) — spec for the PoC testbed harness (dev-facing).
- [`docs/USAGE_GUIDE.md`](docs/USAGE_GUIDE.md) — **superseded by TEAM_GUIDE.md**; kept for history, describes a retired cloud/API-key workflow.
- [`tools/LIBRARY_BUILD_NOTES.md`](tools/LIBRARY_BUILD_NOTES.md) — per-library build flags for PoCs.

## Quick start

Requirements: Python 3 + `httpx`, the `rg` (ripgrep) binary on PATH, and a
running [Ollama](https://ollama.com) server with the investigator model pulled.

```bash
pip install -r requirements.txt          # httpx is the only hard Python dep
ollama pull deepseek-r1:14b              # default investigator + reviewer model

# LLM-led discovery + review on a local source tree:
python3 main.py --target /path/to/wolfssl --library wolfssl --mode agent-review
```

The original tool-led phase pipeline is still the default `--mode`:

```bash
python3 main.py --target /path/to/wolfssl --library wolfssl --phases all
```

Anthropic backend (dormant; opt-in, never takes a key inline):

```bash
export ANTHROPIC_API_KEY=sk-...
python3 main.py --target ./wolfssl --library wolfssl --backend anthropic
```

Check a fresh box before a real run with `--doctor` (prints which analysis tools
are installed for the library's language, then exits without running).

Offline self-tests (no key, no network): `python3 test_offline.py` and
`python3 test_researcher.py`.

### Web UI (optional)

Prefer a browser? A local web frontend wraps this same CLI:

```bash
pip install -r requirements.txt          # includes Flask for the web UI
python3 web/app.py                        # → http://127.0.0.1:5000
```

Submit a **GitHub URL**, a **local path**, or a **drag-and-dropped folder**; it
**auto-detects the library** from the target's own symbols, runs the scan, and
gives you a **scan-history browser** and a rich **result viewer** (severity
summary, Scope & Coverage table, findings with CWE/CVSS/evidence). It shells out
to `main.py`, so every web scan lands in `runs/` exactly like a CLI run. See
[`web/README.md`](web/README.md).

Each run writes to `runs/<lib>/<timestamp>/` (with `runs/<lib>/latest` symlinked
to the newest): `report.html` / `report.md` / `report.json`, plus a `run.log`
(full console log) and a `run.json` manifest (command, target git commit,
backend/model, per-stage timings, token usage). Every report opens with a
**Scope & Coverage** section — a per-entry-point disposition table (`examined —
cleared` / `flagged` / `symbol not found`), per-pass risky-line counts, and a
plain-language reading of a 0-finding result as a deliberate true-negative — so a
clean run shows what was examined instead of a blank page. Add `--explain` to
also emit a **Triage Log**: the candidates the investigator examined and
*dismissed*, each with its reason (unverified model commentary, shown for
transparency).

## Adding a new library

Each scannable library is one self-contained TOML file in `libraries/`. To add a
library, drop in a new `libraries/<name>.toml` — **no code change**. The file
stem is the name you pass to `--library` (lowercased), so `libraries/mylib.toml`
is scanned with `--library mylib`.

```toml
# libraries/mylib.toml
lang = "c"                    # required: one of c, cpp, java, go, boringssl

# Curated crypto entry points — the decaps/encaps/keygen/verify functions the
# investigator anchors on. Keep this a lean, high-signal set (~7–15 symbols);
# dynamic symbol discovery handles breadth beyond these.
entry_points = [
    "mylib_kem_decapsulate",
    "mylib_kem_encapsulate",
    "mylib_sig_verify",
]

# Optional: provider-layer entry points for the PKI discovery surface
# (cert-path validation / OCSP-CRL revocation / keystore loading). Only used
# when you run with PQC_DISCOVERY_PASSES=pki. Omit entirely if not applicable.
# pki_entry_points = ["checkCertificate", "validatedOcspResponse"]
```

Field reference:

| Field | Required | Meaning |
|-------|----------|---------|
| `lang` | yes | Source language; picks the file globs to search. One of `c`, `cpp`, `java`, `go`, `boringssl` (see `LANG_GLOBS` in `config.py`). |
| `entry_points` | no (recommended) | Crypto functions to anchor the hunt on. Omit and the run is discovery-only. |
| `pki_entry_points` | no | Provider-layer anchors for the opt-in `pki` surface. |

Then run it like any other library:

```bash
python3 main.py --target /path/to/mylib --library mylib --mode agent-review
```

Notes:

- **Validation is strict and loud.** A missing/empty `lang`, an unknown `lang`,
  or a non-list entry-point field raises a clear error at startup — a typo can't
  silently degrade the run. Confirm your file loads with
  `python3 -c "import config; print(config.get_library('mylib'))"`.
- **New language?** If your library isn't C/C++/Java/Go, add a `LANG_GLOBS`
  entry in `config.py` first (that map is language-level, not per-library).
- **No entry points yet?** Any `--library` name without a curated file still
  works — it runs discovery-only, where symbol enumeration drives the hunt. The
  TOML just gives the investigator high-signal anchors to start from.
- **Check your entry points resolve.** Prefer specific, uniquely-named symbols
  over generic ones (`Dilithium_Verification_Operation`, not `verify`) — a generic
  name can silently anchor on the wrong file (a test shim, another algorithm, or
  an unrelated module). After a run, the report's **Scope & Coverage** table shows
  a `symbol not found in target` (or off-target) disposition for any entry point
  that didn't resolve to the intended code — fix those by renaming to the real
  symbol.

## Two analysis layers

**1. Researcher pipeline (LLM-led)** — full detail in [MODES.md](MODES.md). An
investigator persona forms hypotheses and drives read-only tools to confirm or
kill them; a *stateless, evidence-only* reviewer re-derives each verdict and
**annotates rather than deletes** (a disputed finding stays, demoted and
labelled `[DISPUTED]`, so a bad review can't silently drop a real bug).

| Mode (`--mode`) | Flow | Tools? | Reviewer? |
|------|------|--------|-----------|
| `reason` | investigator one-shot | no | no |
| `agent` | investigator drives tools | yes | no |
| `agent-review` | investigator → reviewer → report | yes | yes |
| `interactive` | investigator → **human checkpoint** → reviewer → report | yes | yes |

Discovery runs **multi-pass** — one focused pass per crypto surface
(`kem` / `sig` / `sampling`), unioned — so it stops fixating on the same 1-2
findings every run. Configurable via `PQC_DISCOVERY_PASSES` (set to `all` for the
original single call). A bug surfaced by more than one pass is kept once and
tagged as cross-pass corroborated.

**2. Phase pipeline (tool-led, `--phases`, default `--mode`)** — the original
orchestrated flow:

```
OrchestratorAgent                  phase sequencing + escalation
  ├── StaticAnalysisAgent          flawfinder/cppcheck/clang/semgrep + LLM spec review (FIPS 203/204)
  ├── DifferentialAgent            target vs liboqs; FO implicit-rejection aware
  ├── FuzzingAgent                 per-entry-point libFuzzer/AFL harness → run → triage
  ├── TimingAgent                  dudect harness → Welch t → flag |t|>4.5
  ├── ReproductionAgent            minimize repro + ASan&Valgrind confirm + impact triage
  └── ReportAgent                  report.json + report.md (CVSS + validation_status)
```

**Escalation** (`agents/orchestrator.py`): static HIGH/CRITICAL → fuzzing +
differential; fuzzing crash → reproduction; timing HIGH/CRITICAL → reproduction.
Requested phases plus escalated phases run in dependency order; the report phase
always runs.

## Local model roster

All local via Ollama, loaded **serially** so a 16 GB GPU is never over-committed.

| Model | Role | Notes |
|-------|------|-------|
| `deepseek-r1:14b` | investigator + reviewer (default) | general reasoning model |
| `axonvertex/Foundation-Sec-8B-Reasoning` | investigator candidate | security-tuned (Cisco Foundation-Sec, Llama-3.1-8B + cyber pretrain); primed via `MODEL_SETTINGS` |
| `DeepHat/DeepHat-V1-7B` | PoC drafter (`--poc`) | security-tuned code model |

A/B two investigator models on identical evidence — each finding is tagged with
the model that produced it (`discovered_by`):

```bash
python3 main.py --target ~/wolfssl --library wolfssl --mode reason \
  --compare-models "deepseek-r1:14b,axonvertex/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:Q8_0_24K"
```

Per-model generation settings (temperature, context window, role addendum) live
in `config.MODEL_SETTINGS`; discovery calls run at `DISCOVERY_TEMPERATURE` (0.7).
The investigator timeout is `OLLAMA_TIMEOUT` (2700 s) to give reasoning models
room on a cold load.

## Design decisions preserved from the handover

1. **Pre-filter tool output** (cap ~4000 chars, drop noise) before the LLM
   (`core/prefilter.py`).
2. **FO implicit rejection is expected** — `DifferentialAgent` classifies every
   vector by input class and never flags corrupted-ciphertext divergence; it
   only flags valid-input disagreement and key-validation differences.
3. **Dual memory confirmation** — `ReproductionAgent` requires ASan *and*
   Valgrind on the same reproducer before marking a finding `confirmed`.
4. **Artifacts on disk** — harnesses, reproducers, and logs are written under
   `runs/<ts>/<phase>/` for researcher review, never just printed.

> **Generation temperature is no longer a flat 0.2.** The earlier "0.2 on every
> call" actually dropped caller-supplied settings and ran every call at Ollama's
> default 0.8, which wrecked structured/code output on small models. Settings are
> now applied per-model (`config.MODEL_SETTINGS`) and per-call (discovery 0.7) in
> `core/llm.py`.

## Validation targets

A correct run rediscovers all three (see `validation_status` in the report);
these are specific to the wolfSSL 5.9.1 handover snapshot:

| ID | Where | Found by phase |
|----|-------|----------------|
| WF-001 | `random.c` weak `srand(time(NULL))` seed | static (grep + confirm) |
| WF-004 | `mlkem_check_public` misses NTT validity | static spec review / differential |
| CVE-2026-5460 | heap UAF in TLS PQC hybrid key-share | fuzzing → reproduction |

## Scope of the reproduction agent (read before extending it)

`ReproductionAgent` produces what a vendor disclosure needs: a **minimized
reliable reproducer**, **dual-tool confirmation**, and an **impact
classification** (read vs. write, UAF vs. overflow, controllability band) for
CVSS. It deliberately does **not** generate weaponized exploits — no heap
grooming, ROP/JOP, ASLR/DEP bypass, or payloads. The "crash-only vs.
RCE-potential" question is answered at the level of classification to inform
severity, not by building an exploitation primitive. Keep weaponization
human-in-the-loop.

## Wiring real targets

The fuzzing/timing/reproduction agents compile harnesses against the target.
Supply the include/object flags your build needs:

```bash
python3 main.py --target ./wolfssl --library wolfssl --phases static \
  --build-flags -I./wolfssl -L./wolfssl/src/.libs -lwolfssl \
  --valgrind-binary ./build-noasan/harness_wc_MlKemKey_Decapsulate
```

`liboqs-python` enables the differential oracle: `pip install liboqs-python`.

## Open research hooks

- Spec text vs. parametric knowledge (problem #1): drop `specs/fips203.txt` /
  `fips204.txt` to enable the full-text arm; `specs/fips_refs.py` switches
  automatically so you can A/B detection accuracy.
- FO disambiguation (problem #2): input-class table in `agents/differential.py`.
- Timing under virtualisation (problem #3): `TimingAgent` re-runs and downgrades
  inconsistent leaks to `suspected`; run on bare metal to confirm.

## Responsible disclosure

All artifacts are for CVE reporting and coordinated disclosure to the affected
vendor's security team. Confirm with the researcher before any public release.

## Changelog

Moved to **[CHANGELOG.md](CHANGELOG.md)** — release notes, newest first.
