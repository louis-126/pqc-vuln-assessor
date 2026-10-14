# PQC Vulnerability Assessor — Team Usage Guide

A multi-agent system that security-audits post-quantum crypto libraries
(ML-KEM / ML-DSA) and produces disclosure-ready reports. An LLM "investigator"
drives real analysis tools to hunt bugs; a stateless "reviewer" independently
verifies each finding; a "resolution" loop chases down anything that needs more
evidence. Output is an HTML + Markdown report.

---

## 1. One-time setup (each team member)

### Install dependencies
```bash
# Python package
pip install httpx

# Required: ripgrep (code navigation)
sudo apt install ripgrep        # Debian/Ubuntu/WSL
# pip install ripgrep          # macOS (in venv)

# Optional but recommended (static analysis tools the investigator can call)
sudo apt install flawfinder cppcheck clang

# Optional (only for the phase pipeline: fuzzing / timing / reproduction)
sudo apt install afl++ valgrind
```

### Get an API key
Each person needs their own Anthropic API key from
**console.anthropic.com → API Keys**. The program reads it from the environment
— it is never stored in the code.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Add that line to your `~/.bashrc` (or `~/.zshrc`) so it persists.

> **Billing note:** usage bills to whoever owns the key in the command's
> environment. If you share one team key, all runs bill to that key's owner.
> Set a spend cap under **console.anthropic.com → Billing → Usage limits**.

### Verify the install
```bash
cd pqc_assessor
python3 test_researcher.py     # should print AGENT-REVIEW PIPELINE OK
python3 test_offline.py        # should print ALL OFFLINE TESTS PASSED
```

---

## 2. Supported libraries

| `--library` | Language | Get the source |
|---|---|---|
| `wolfssl` | C | `git clone https://github.com/wolfSSL/wolfssl` |
| `openssl` | C | `git clone https://github.com/openssl/openssl` |
| `boringssl` | C/C++ | `git clone https://boringssl.googlesource.com/boringssl` |
| `liboqs` | C | `git clone https://github.com/open-quantum-safe/liboqs` |
| `botan` | C++ | `git clone https://github.com/randombit/botan` |
| `bouncycastle` | Java | `git clone https://github.com/bcgit/bc-java` |
| `circl` | go | `git clone https://github.com/cloudflare/circl.git` |

The tool auto-detects the source language and searches the right file types
(`.c/.h`, `.cpp/.cc`, `.java`, etc.). Each library has built-in "known location"
hints so the investigator goes straight to the PQC code instead of wasting
API calls exploring.

> Only wolfSSL has a built-in validation set (the three known bugs WF-001,
> WF-004, CVE-2026-5460) used as a self-test. For every other library the
> report simply lists findings on their own merits — there is no pass/fail
> validation table.

---

## 3. Running an assessment

### Basic command
```bash
python3 main.py --target /path/to/source --library <name> --mode agent-review --cost-saver
```

### The modes (`--mode`)

| Mode | What it does | When to use |
|---|---|---|
| `reason` | LLM reads code once, no tools | Quick cheap sanity pass |
| `agent` | LLM drives tools, no review | Fast hunt, no verification |
| `agent-review` | Hunt → independent review → auto-resolve evidence | **Default — use this** |
| `interactive` | Same, but you triage findings + steer the reviewer | High-stakes manual runs |

### Recommended commands

**Standard run (cheap, verified):**
```bash
python3 main.py --target /home/you/openssl --library openssl \
  --mode agent-review --cost-saver --max-turns 16 -q
```

**Interactive run (you review findings before the reviewer, and can give it
instructions):**
```bash
python3 main.py --target /home/you/botan --library botan \
  --mode interactive --cost-saver --max-turns 16
```
At the checkpoint you can keep/drop findings and type guidance like
`focus on the decaps path, ignore anything under tests/`.

**Final disclosure-quality run (uses the stronger Opus model — drop
`--cost-saver`):**
```bash
python3 main.py --target /home/you/wolfssl --library wolfssl \
  --mode agent-review --max-turns 20
```

### Useful flags
| Flag | Effect |
|---|---|
| `--cost-saver` | Use the cheaper Sonnet model (use for iteration) |
| `-q` / `--quiet` | Minimal output — just progress and results |
| `-v` / `--verbose` | Full debug output (HTTP + every tool call) |
| `--max-turns N` | Cap the investigator's tool-loop length (default 16) |
| `--outdir PATH` | Where to write the run (default `runs/<timestamp>`) |
| `--doctor` | Print which analysis tools are installed for the library's language, then exit (no run). Use to check a fresh box before a real run. |
| `--explain` | Also record the investigator's *examined-and-dismissed* candidates with reasons — a **Triage Log** in the report. Model commentary, unverified; small extra token cost. |

---

## 4. Reading the output

Each run writes to `runs/<lib>/<timestamp>/` (and `runs/<lib>/latest` is a
symlink to the most recent auto-named run):

- **`report.html`** — open in a browser. Colour-coded severity, collapsible
  evidence, proposed fixes, review verdicts. This is the one to read.
- **`report.md`** — same content as plain Markdown (for pasting into issues).
- **`report.json`** — machine-readable, for scripting (now also carries the
  `coverage` and `triage` data).
- **`run.log`** — the full console log of the run (what was gathered, flagged,
  grounded), always written even on a `-q` run.
- **`run.json`** — a run manifest: command, target git commit, backend/model,
  timings per stage, finding counts, and token usage.

### Scope & Coverage (every report)

Above the findings, every report shows a **Scope & Coverage** section so a clean
(0-finding) run demonstrates the work done instead of reading as if nothing ran:

- **Entry-point coverage** — a per-entry-point disposition table: `examined —
  cleared`, `flagged — see findings`, or `symbol not found in target`. This is
  how you spot a curated entry point that doesn't resolve in a given library.
- **Per-pass triage** — how many risky lines each discovery pass flagged and how
  many findings were grounded.
- A plain-language note reading a 0-finding result as a deliberate true-negative
  (the scan ran to completion) rather than a skipped or errored run.

### Triage Log (`--explain` only)

With `--explain`, the report adds a **Triage Log**: the specific candidate
locations the investigator examined and *dismissed*, each with its one-line
reason (e.g. *"branch is on key-format length, not secret"*). This is the model's
own explanation — it is **unverified model commentary**, shown for transparency,
**not** a grounded verdict.

### Understanding a finding
Each finding shows:
- **Severity** (CRITICAL → INFO) and **phase** it came from
- **Confidence**: `confirmed` (reviewer verified), `suspected` (unverified),
  or `[DISPUTED]` (reviewer pushed back — demoted, but kept so nothing is
  silently lost)
- **Replication** — how to trigger it
- **Proposed fix** — the suggested code change
- **Review verdict** — the independent reviewer's reasoning

A `confirmed` finding has been independently re-derived from raw evidence by a
second pass that never saw the investigator's reasoning. A `needs-evidence`
finding triggered the auto-resolution loop, which read the specific lines the
reviewer asked for and re-judged.

---

## 5. Cost guide

Rough per-run cost with `--cost-saver` (Sonnet):
- `reason`: ~$0.05
- `agent` / `agent-review`: ~$0.30–0.60
- Without `--cost-saver` (Opus): roughly 5× the above

Tips to keep cost down:
- Use `--cost-saver` for all iteration; switch to Opus only for the final run.
- Keep `--max-turns` at 16 unless a run is genuinely getting cut off.
- Use `agent-review` over `interactive` when iterating (no waiting at prompts).

---

## 6. Team workflow suggestion

1. **Assign libraries** — one person per library avoids duplicate API spend.
2. **Iterate with `--cost-saver`** until the findings look solid.
3. **Final pass on Opus** (drop `--cost-saver`) for the disclosure report.
4. **Share the `runs/<timestamp>/` folder** — it contains the HTML report and
   all evidence/artifacts.
5. **Before disclosing**, manually verify the confirmed findings (build the
   library, reproduce the bug). The tool finds and reasons about bugs; a
   disclosure still needs a human-verified proof-of-concept.

### Network note
The only outbound connection is HTTPS to `api.anthropic.com`. On a corporate or
university network, make sure that isn't blocked.

---

## 7. Responsible disclosure

Every finding is for coordinated disclosure to the affected library's security
team. Confirm with the team lead before any public release. The tool produces
reproduction sketches and impact analysis — not weaponized exploits — by design.
