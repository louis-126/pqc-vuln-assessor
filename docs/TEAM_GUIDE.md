# PQC Vulnerability Assessor — Team Setup & Usage Guide

A pipeline that security-audits post-quantum crypto libraries (ML-KEM / ML-DSA)
using **local, free** LLMs and produces a disclosure-style report. An LLM
"investigator" gathers and analyses the crypto code, a stateless "reviewer"
independently re-checks every finding against the real source, and a
"resolution" loop chases anything that needs more evidence. Output is an
HTML + Markdown + JSON report.

> **Scope of this guide:** setup → run → read the report. It covers the
> **bug-finding and reporting** features, which are the working part of the tool.
> The PoC "prove it" stage (`--poc`, the generated client/server demo) is **not
> working yet — do not use it.** See the last section.

> **No API key, no cloud, no cost.** Everything runs locally through Ollama.
> Ignore the older `USAGE_GUIDE.md` if you see it — it describes a retired
> cloud/API-key workflow and is out of date.

---

## 1. One-time setup (each machine)

### 1a. Hardware
Built and tuned for a **16 GB-VRAM GPU** (e.g. RTX 4060 Ti 16 GB) on
Windows + WSL Ubuntu. Models load **one at a time** (serially), so a 16 GB card
is enough even when the investigator and reviewer use different models.

### 1b. Install Ollama and the models
```bash
# Install Ollama (https://ollama.com) — runs a local model server on :11434
curl -fsSL https://ollama.com/install.sh | sh

# Pull the two models the pipeline uses:
ollama pull deepseek-r1:14b          # investigator + reviewer (the proven winner)
ollama pull deepseek-coder-v2:16b    # optional: independent reviewer model

# Make sure the server is running (usually automatic):
ollama serve   # leave running, or it starts on demand
ollama list    # confirm the models are present
```

### 1c. Install the support tools
```bash
# Python dependency:
pip install httpx

# REQUIRED — ripgrep powers all code search/discovery (this is what gives the
# tool whole-library coverage):
sudo apt install ripgrep

# Recommended — static analysers the investigator can call:
sudo apt install clang cppcheck flawfinder
pip install semgrep
```
> **Joern is NOT required.** It's an optional data-flow tier that is **off by
> default** (it needs more work before it adds value). You can ignore it.

### 1d. Verify the install
```bash
cd /mnt/p/ITP/LLM
python3 test_offline.py       # -> ALL OFFLINE TESTS PASSED
python3 test_researcher.py    # -> AGENT-REVIEW PIPELINE OK
```
If both pass, you're ready. (The `'go'/'staticcheck'/'gosec' not in PATH` and
`'joern' not in PATH` lines are normal — those tools are optional.)

### 1e. Models we tested — and what to use

You only need **`deepseek-r1:14b`** (and optionally `deepseek-coder-v2:16b` as
an independent reviewer). The rest of this table is the record of what was
tried so nobody re-treads dead ends. All sizes are the on-disk model size;
anything near or above ~16 GB offloads to CPU on a 16 GB card and gets slow.

| Model | Size | Tried as | Verdict |
|---|---|---|---|
| **`deepseek-r1:14b`** | 9 GB | analyst + reviewer + report enrichment | ✅ **WINNER — the default.** Produces grounded findings (real file:line with supporting quotes), fits 16 GB comfortably. |
| **`deepseek-coder-v2:16b`** | 8.9 GB | reviewer | ✅ **Keep.** Good independent reviewer — pass it via `--reviewer-model`. |
| `DeepHat/DeepHat-V1-7B` | 15 GB | uncensored PoC drafter | ⚠️ Drafts PoC C, but truncates JSON (needs the plain-text fallback) and the **PoC stage isn't ready** — not used for bug-finding. |
| `mistral-small` | 14 GB | analyst backup | ❌ Confabulates / returns empty. Low value — safe to delete. |
| `qwen3-coder:30b` | 18 GB | old investigator | ❌ **Drop.** Confabulates and doesn't fit 16 GB (offloads, slow). |
| `gpt-oss:20b` | 13 GB | candidate | ❌ Timed out at the old 600s limit; 13 GB offloads on a 16 GB card — low return. |
| `axonvertex/Foundation-Sec-8B-Reasoning-Q8_0-GGUF` | 8.5 GB | candidate **investigator** (security-tuned: Llama-3.1-8B + cyber pretrain + reasoning) | 🟢 **Primed & functional.** Now has a `MODEL_SETTINGS` entry (PQC-analyst role prompt; `num_ctx` pinned to its 24K window so it fits VRAM). Confirmed it loads & reasons correctly (~14 tok/s; cold load ~330s, ~100s warm). The old "600s timeout" was the cold weight load, not a real failure. **Head-to-head vs deepseek-r1 still pending** — run `--compare-models`. |
| `dolphin3:8b`, `qwen2.5-coder:14b` | — | early candidates | ❌ Deleted — superseded by deepseek-r1. |

> The investigator timeout was raised to **2700s** (`OLLAMA_TIMEOUT` in
> `config.py`), so the two "timed out at 600s" candidates above
> (`Foundation-Sec-8B-Reasoning`, `gpt-oss:20b`) were never given a fair run.
> `Foundation-Sec` has since been primed (see its row) and confirmed working. To
> evaluate a new analyst model, test it head-to-head on the same target with
> `--compare-models "deepseek-r1:14b,<candidate>"` — each finding is tagged with
> the model that produced it, so you can compare grounded output directly. To run
> it as the SOLE investigator instead, pass `--ollama-model <candidate>`.

---

## 2. Get a target library to scan

Clone whichever library you're assigned:

| `--library` | Language | Clone |
|---|---|---|
| `wolfssl` | C | `git clone https://github.com/wolfSSL/wolfssl` |
| `liboqs` | C | `git clone https://github.com/open-quantum-safe/liboqs` |
| `openssl` | C | `git clone https://github.com/openssl/openssl` |
| `boringssl` | C/C++ | `git clone https://boringssl.googlesource.com/boringssl` |
| `botan` | C++ | `git clone https://github.com/randombit/botan` |
| `bouncycastle` | Java | `git clone https://github.com/bcgit/bc-java` |
| `circl` | Go | `git clone https://github.com/cloudflare/circl` |

You do **not** need to build the library for bug-finding — the tool reads source.
(Building the library is only needed if you use `--poc` and want to actually
compile/run the generated PoC scaffold — see section 6.)

> **Note:** wolfSSL is the best-tested target. liboqs vendors its real crypto
> from PQClean, so discovery looks under `src/kem/ml_kem/pqclean_*/clean/`.

---

## 3. Run an assessment

### The standard command
```bash
cd /mnt/p/ITP/LLM
python3 main.py --library wolfssl --target /home/you/wolfssl \
  --ollama-model deepseek-r1:14b \
  --cache-reads --verbose 2>&1 | tee /tmp/run.log
```

### Recommended: add an independent reviewer
By default the same model reviews its own findings ("two passes of one model").
For a genuinely independent check, give the reviewer a different model family:
```bash
python3 main.py --library wolfssl --target /home/you/wolfssl \
  --ollama-model deepseek-r1:14b \
  --reviewer-model deepseek-coder-v2:16b \
  --cache-reads --verbose 2>&1 | tee /tmp/run.log
```
(Models load serially, so this is 16 GB-safe but adds model-swap time.)

### Key flags
| Flag | Effect |
|---|---|
| `--library <name>` | **Required.** One of the 7 above. |
| `--target <path>` | **Required.** Path to the cloned source tree. |
| `--ollama-model <m>` | Investigator + reviewer model (default `deepseek-r1:14b`). |
| `--reviewer-model <m>` | Use a *different* model for the reviewer (recommended). |
| `--cache-reads` | Cache repeated file reads within a run (faster). |
| `--verbose` / `-v` | Show live progress + every step (useful). |
| `--quiet` / `-q` | Minimal output. |
| `--compare-models "a,b"` | A/B discovery: run two models on the same evidence; each finding is tagged with the model that produced it. |
| `--outdir <path>` | Override the output location. |

> **Optional: `--poc`** generates a documented PoC *package* (C client/server +
> README + build script) for each confirmed finding, for **you** to build and run
> in a sandbox — the tool no longer compiles or runs anything itself. Adds time
> (extra model calls). See section 6.

### How the program works (the pipeline)
The run prints boxed stages. What each one does:

1. **Investigation** — *deterministically* gathers the crypto code from across
   the **whole source tree** (this is what ripgrep does, not Joern): the bodies
   of the per-library entry points, role-based symbol discovery (decap/encap/
   keygen/sign/verify/ntt/rng…), and **one level of "callee expansion"** into
   security-critical helpers (so the model sees the real implementation a call
   points at, not just the call site). The investigator model then analyses that
   evidence and emits findings. Every finding is filtered through grounding
   guards: the file must exist, the quoted line must actually appear in the
   gathered code **at the claimed location**, it must be PQC-scoped, and
   duplicates are collapsed.
2. **Review** — a stateless reviewer (ideally a *different* model via
   `--reviewer-model`) re-reads the real source at each finding's location and
   re-derives a verdict from scratch. To be `confirmed` it must supply a
   spec_clause + proving_line + claim_justification + cvss_vector; it's
   auto-demoted if the proving_line is just a function *call*, or if the cited
   spec operation contradicts the code (e.g. a decaps rule on encaps code).
3. **Resolution** — for `needs-evidence` findings, fetches the specific function
   bodies the reviewer asked for and re-reviews (1–2 rounds).
4. **Report** — enriches each finding (impact, attack scenario, remediation) and
   writes `report.html` / `.md` / `.json`.
5. **PoC package** *(only with `--poc`)* — for each `confirmed` finding,
   generates a documented client/server scaffold for **you** to build and run
   (section 6). The tool does not compile or run anything.

**Expect roughly 45–90 minutes** on a 16 GB card (longer with `--reviewer-model`
and `--poc`, which add model swaps and extra calls). It is **not hung** — local
14B/16B models are just slow; the investigation stage alone is ~20–30 min.

---

## 4. Read the report

Each run writes to **`runs/<library>/<timestamp>/`**:

- **`report.html`** — open in a browser. Colour-coded severity, evidence,
  proposed fixes, reviewer verdicts. **This is the one to read.**
- **`report.md`** — same content as Markdown (for pasting into issues/Slack).
- **`report.json`** — machine-readable, for scripting.

### Confidence levels — what they mean
| Label | Meaning |
|---|---|
| `confirmed` | The reviewer independently re-derived it from the real code **and** it passed all the grounding gates (see below). The strongest signal — but still verify by hand before disclosure. |
| `suspected` | Emitted but not verified (no reviewer confirmation). A lead. |
| `needs-evidence` | The reviewer couldn't confirm/deny; the resolution loop tried to fetch more code. |
| `[DISPUTED]` | The reviewer pushed back — the cited code doesn't support the claim. Kept (demoted) for transparency, **most likely a false positive.** |

### Why "confirmed" is meaningful now
A finding only reaches `confirmed` if the reviewer supplies, and the code checks:
- a **spec_clause** (which FIPS 203/204 algorithm/rule is violated),
- a **proving_line** (the verbatim vulnerable line — a bare function *call* is
  rejected as not-proof),
- a **claim_justification** (how that line shows the specific bug), and
- a **cvss_vector** (so the report carries a real CVSS score, not 0.0).

It's also auto-demoted if the cited spec operation doesn't match the code (e.g.
a decapsulation rule cited on encapsulation code). These guards exist to stop
the model rubber-stamping plausible-but-wrong findings.

### Each finding shows
Severity (CRITICAL→INFO), location (`file:line`), CWE, the spec clause, a
description, the **evidence_quote**, a **proposed fix**, and the **reviewer's
verdict + reasoning**.

---

## 5. Team workflow

1. **Assign one library per person** to avoid duplicate effort.
2. **Run with `--reviewer-model`** for the independent-review benefit.
3. **Triage the report**: focus on `confirmed`, read `[DISPUTED]` to learn the
   false-positive patterns, treat `suspected` as leads.
4. **Manually verify** any confirmed finding before it goes anywhere — build the
   library and reproduce. The tool generates *grounded hypotheses*, not proof.
5. **Share the `runs/<library>/<timestamp>/` folder** — it has the report and all
   evidence.
6. **Sanity-check spec citations** against the published FIPS 203/204 PDFs before
   putting a clause number in a disclosure — the tool cites by algorithm name to
   reduce errors, but a human should confirm any exact section number.

---

## 6. The PoC package stage (`--poc`) — optional

With `--poc`, after the report the tool writes a **PoC package per confirmed
finding** to `runs/<lib>/<ts>/poc/<finding_id>/`:

| File | What it is |
|---|---|
| `README.md` | What the PoC is, the vulnerability, what it does, **how to run it**, the expected result, and the suggested fix. |
| `server.c` | Uses the library normally; runs the vulnerable operation on data from the client. |
| `client.c` | The attacker; sends crafted input to trigger the bug. |
| `poc_net.h` | Fixed localhost-TCP transport (don't edit). |
| `build.sh` | The compile command (with discovered include/lib paths). |

**The tool does NOT compile or run the PoC — you do.** In a sandbox with the
library built/installed:
```sh
cd runs/<lib>/<ts>/poc/<finding_id>/
sh build.sh            # compile (edit paths if needed)
./poc_server 21000 &   # start the server
./poc_client 21000     # run the attacker
```
Then check the README's "Expected result" for what proves the bug (a server
crash, an accepted-bad-input, or a timing difference).

> **It's a scaffold, not a finished exploit.** Local models can't reliably write
> compile-ready code against a complex crypto library — treat `server.c`/
> `client.c` as a starting point you review and adjust to your library version.
> The tool documents the vulnerability; **you** confirm the PoC.
>
> Skip `--poc` if you just want findings — it adds several minutes of model time.

**Joern data-flow slicing** — off by default; needs a source-aware query before
it adds value. Leave it off.

So the honest pitch of what works today: it **systematically generates grounded,
spec-referenced PQC vulnerability hypotheses on free local models, independently
reviews them to filter false positives, produces a disclosure-style report, and
hands you documented PoC scaffolds to build and confirm.** A human still owns the
final proof-of-concept and disclosure decision.

---

## 7. Known problems & limitations (read this)

Be honest with yourself and your team lead about what this tool is. Current
state, as of this guide:

- **Findings are hypotheses, not proof.** The review + grounding guards filter a
  lot of false positives, but local models still confabulate. **Every
  `confirmed` finding must be manually verified** before it goes anywhere.
- **It's slow.** ~45–90 min per run on a 16 GB card; the investigator is the
  bottleneck (inherent to local 14B/16B inference — models load serially, so
  `--reviewer-model` and `--poc` add swap time). Not hung, just slow.
- **PoC code is a 7B scaffold, not a finished exploit.** The drafter
  (DeepHat-V1-7B) produces plausible, well-structured C, but it **frequently
  guesses internal/private function signatures wrong**, may have minor type/logic
  errors, and is most reliable on public API entry points. **You must review and
  fix `server.c`/`client.c` before they compile/run.** The README says this too.
- **PoC build needs the library compiled** (`libwolfssl.a` etc.); `build.sh`
  include/lib paths may need adjusting to your install.
- **Default reviewer is self-review.** Without `--reviewer-model`, the same model
  reviews its own findings — weaker assurance. Always pass a different reviewer
  model.
- **Cross-function data-flow (Joern) is OFF.** Coverage is name/role-based plus
  one level of callee expansion, so some genuinely multi-function bugs are out of
  reach. Joern needs a source-aware query before it adds value.
- **Spec section numbers aren't guaranteed.** The tool cites by *algorithm name*
  (e.g. `ML-KEM.Decaps`) to avoid wrong `§` numbers; **verify any exact section
  number against the published FIPS 203/204 PDFs** before disclosure.
- **wolfSSL is the best-tested target.** liboqs / botan / circl / bc-java work but
  have had far less real-run validation — expect rougher results.
- **Recent change to watch:** all models now honor the temperature passed to them
  (previously ignored — everything ran hot at 0.8). Generally an improvement, but
  it's new; if a model's output quality shifts, that's why.

---

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `connection refused` / no model response | `ollama serve` not running, or model not pulled. Run `ollama list`. |
| Run is extremely slow / swapping | Two big models don't co-reside on 16 GB; they load serially (expected). Close other GPU apps. |
| `ripgrep`/`rg` errors, no findings | Install ripgrep (`sudo apt install ripgrep`) — discovery depends on it. |
| `0 findings` | Check the `--target` path is the source root and `--library` matches it. Try `--verbose` to see what was gathered. |
| Garbled box characters in a piped log | Cosmetic (the telemetry boxes); the report files are unaffected. |
| Want to re-enable Joern (advanced) | `PQC_ENABLE_JOERN=1` prefix **and** `joern`/`joern-parse`/`joern-slice` all on PATH. Not recommended yet. |

---

## 9. Responsible use

Every finding is for **coordinated disclosure** to the affected library's
security team. Confirm with the team lead before any public mention. The tool
produces reproduction sketches and impact analysis for disclosure — not
weaponised exploits — by design.
