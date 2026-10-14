# Two-layer researcher pipeline

A second analysis style alongside the original tool-led `--phases` pipeline.
Here the **LLM leads** and the deterministic tools serve it.

## The two layers

1. **Investigator** (`agents/researcher.py`) — a senior-PQC-researcher persona
   that forms hypotheses and drives tools (`core/tools.py`) to confirm or kill
   them, then emits findings with an evidence trail.
2. **Reviewer** (`agents/reviewer.py`) — a *stateless, evidence-only* second
   pass. It does NOT see the investigator's reasoning chain — only the claim +
   raw evidence — so it must re-derive each verdict. It **annotates, never
   deletes**: a disputed finding stays in the report, demoted and labelled
   `[DISPUTED]`, so a bad review can't silently drop a real bug.

## Modes (`--mode`)

| Mode | Flow | Tools? | Reviewer? |
|------|------|--------|-----------|
| `reason` | investigator one-shot | no | no |
| `agent` | investigator drives tools | yes | no |
| `agent-review` | investigator → reviewer → report | yes | yes |
| `interactive` | investigator → **human checkpoint** → reviewer → report | yes | yes |

`phases` (default) is the original tool-led pipeline, unchanged.

## Interactive checkpoint

After the investigator finishes, you can:
- **triage** — type which finding numbers to keep (`1,3`, `all`, or `none`/`abort`)
- **guide** — type a free-text instruction the reviewer is *bound to follow*
  (e.g. "focus on the decaps path, ignore anything under test/")

## Tools the investigator can call

Read-only / analysis only — no weaponization:
`read_file`, `search_code` (ripgrep), `find_callers`, `git_blame`,
`run_flawfinder`, `run_cppcheck`, `run_clang_analyzer`, `run_semgrep`.

Add a tool = one `Tool` entry in `core/tools.py` (CodeQL, Infer, Wycheproof
vectors are stubbed at the bottom). Unavailable tools are auto-hidden from the
model.

## PQC priors

`prompts/pqc_researcher.py` carries the lattice-crypto failure-mode catalogue
(NTT validity vs. range-check, FO implicit rejection, constant-time, rejection
sampling, ML-DSA norm/hint checks, weak RNG, PQC-glue UAF). Treat it as a living
document — fold in manual findings to sharpen it.

## Examples

```bash
# LLM drives tools, no review
python3 main.py --target /home/isaac/wolfssl --library wolfssl --mode agent -v --cost-saver

# Full two-layer
python3 main.py --target /home/isaac/wolfssl --library wolfssl --mode agent-review -v

# Human in the loop before review
python3 main.py --target /home/isaac/wolfssl --library wolfssl --mode interactive -v
```

Offline test (no key/network): `python3 test_researcher.py`
