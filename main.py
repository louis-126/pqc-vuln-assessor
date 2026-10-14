#!/usr/bin/env python3
"""PQC vulnerability assessment — CLI entry point v2.

All v1 flags preserved. v2 adds:
  --backend, --ollama-model
  --multi-model, --draft-model
  --token-budget, --cache-reads
  --poc, --poc-drafter-model, --poc-critic-model

Phases: static, fuzzing, differential, timing, reproduction (or 'all').
"""
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import config
from config import (
    DEFAULT_TOKEN_BUDGET, OLLAMA_MODELS,
)
from core import AssessmentResult, Phase
from core.llm import LLMClient, LLMConfig, TokenTracker, make_backend
from agents import (
    OrchestratorAgent, StaticAnalysisAgent, FuzzingAgent, DifferentialAgent,
    TimingAgent, ReproductionAgent, ReportAgent,
)

ALL_PHASES = [Phase.STATIC, Phase.FUZZING, Phase.DIFFERENTIAL,
              Phase.TIMING, Phase.REPRODUCTION]

# v1 imports preserved
try:
    from core import COST_SAVER_MODEL
except ImportError:
    COST_SAVER_MODEL = "claude-sonnet-4-6"


def parse_phases(spec: str) -> set[Phase]:
    if spec.strip().lower() == "all":
        return set(ALL_PHASES)
    out = set()
    for token in spec.split(","):
        token = token.strip().lower()
        if not token:
            continue
        try:
            out.add(Phase(token))
        except ValueError:
            valid = ", ".join(p.value for p in ALL_PHASES)
            raise SystemExit(f"unknown phase '{token}'. Valid: {valid}, all")
    return out


def build_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="PQC library security assessor v2")

    # ---- v1 flags (all preserved) ----
    # Not argparse-required: --poc-only works off a finished run directory and
    # takes both of these from its run.json. Validated in main() instead.
    p.add_argument("--target", default=None, help="path to library source tree")
    p.add_argument("--library", default=None, metavar="LIBRARY",
                   help="which library. Curated entry points exist for: "
                        + ", ".join(config.library_names())
                        + ". ANY other name is accepted and runs discovery-only "
                          "(symbol enumeration drives the hunt) — no code edit "
                          "needed to point at a new library.")
    p.add_argument("--mode", default="agent-review",
                   choices=["phases", "reason", "agent", "agent-review", "interactive"],
                   help="phases=tool-pipeline (default); reason=LLM one-shot; "
                        "agent=LLM drives tools; agent-review=agent then reviewer; "
                        "interactive=agent, human checkpoint, then reviewer")
    p.add_argument("--phases", default="all",
                   help="comma list or 'all' (static,fuzzing,differential,timing,reproduction)")
    p.add_argument("--max-turns", type=int, default=40,
                   help="max tool-loop turns for the investigator (agent modes)")
    p.add_argument("--model", default=None, help="override LLM model id")
    p.add_argument("--cost-saver", action="store_true",
                   help="use the cheaper Sonnet model for LLM calls")
    p.add_argument("--fuzz-seconds", type=int, default=config.DEFAULT_FUZZ_SECONDS)
    p.add_argument("--timing-repeats", type=int, default=config.DEFAULT_TIMING_REPEATS)
    p.add_argument("--outdir", default=None, help="output dir (default: ./runs/<ts>)")
    p.add_argument("--build-flags", nargs="*", default=[],
                   help="extra clang flags to compile harnesses against the target")
    p.add_argument("--valgrind-binary", default=None,
                   help="path to a non-ASan build for Valgrind confirmation")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="show debug output including HTTP and tool calls")
    p.add_argument("--live", action="store_true", default=True,
                   help="show live progress telemetry (default on)")
    p.add_argument("--no-live", dest="live", action="store_false",
                   help="disable live progress telemetry")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress tool-call lines; only show phase progress and results")
    p.add_argument("--doctor", action="store_true",
                   help="print which analysis tools are installed for --library's "
                        "language, then exit (no run)")
    p.add_argument("--explain", action="store_true",
                   help="also record the investigator's 'examined and dismissed' "
                        "candidates with reasons (a Triage Log in the report). "
                        "Model commentary, unverified; adds a little token cost.")

    # ---- v2: backends ----
    p.add_argument("--backend", default="ollama",
                   choices=["ollama", "anthropic"],
                   help="LLM backend (default: ollama; anthropic kept dormant)")
    p.add_argument("--ollama-model", default="deepseek-r1:14b",
                   metavar="MODEL",
                   help=f"Ollama model for review + report enrichment "
                        f"(default: deepseek-r1:14b). Options: {', '.join(OLLAMA_MODELS)}")

    # ---- v2: multi-model ----
    p.add_argument("--multi-model", action="store_true",
                   help="use different models for investigator vs reviewer/resolution")
    p.add_argument("--draft-model", default=None,
                   help="lighter Ollama model for reviewer/resolution (required with --multi-model)")
    p.add_argument("--reviewer-model", default=None,
                   help="Ollama model for the REVIEWER, ideally a different family "
                        "than the investigator for genuine independence "
                        "(e.g. deepseek-coder-v2:16b). Loads serially (16GB-safe).")


    # ---- v2: cost efficiency ----
    p.add_argument("--token-budget", type=int, default=DEFAULT_TOKEN_BUDGET,
                   help=f"cumulative token budget (default: {DEFAULT_TOKEN_BUDGET:,})")
    p.add_argument("--cache-reads", action="store_true",
                   help="cache tool output per run; repeated reads return cached result")

    p.add_argument("--browse-loop", action="store_true",
                   help="Re-enable the multi-turn agentic browse loop before extraction "
                        "(default off — use only for models with native tool support)")

    # ---- multi-model A/B discovery ----
    p.add_argument("--compare-models", default=None, metavar="M1,M2,...",
                   help="A/B discovery: comma-separated Ollama models run on the "
                        "SAME evidence (serially, 16GB-safe); each finding is "
                        "tagged with the model that produced it. "
                        "e.g. 'deepseek-r1:14b,mistral-small'")

    # ---- v2: PoC generation ----
    p.add_argument("--poc", action="store_true",
                   help="generate PoC harnesses for confirmed findings (internal only)")
    p.add_argument("--poc-only", metavar="RUN_DIR", default=None,
                   help="do NOT scan: generate PoC packages for an already-completed "
                        "run directory (runs/<library>/<timestamp>), reading its "
                        "run.json + report.json. Needs the scanned source tree still "
                        "on disk. --target/--library are not required with this.")
    p.add_argument("--poc-overwrite", dest="poc_overwrite", action="store_true",
                   default=True,
                   help="with --poc-only: replace existing packages (default)")
    p.add_argument("--poc-keep-existing", dest="poc_overwrite", action="store_false",
                   help="with --poc-only: skip findings that already have a package")
    p.add_argument("--poc-drafter-model", default="DeepHat/DeepHat-V1-7B",
                   help="Model for PoC drafting: a local Ollama id (default: "
                        "DeepHat/DeepHat-V1-7B), or a claude-* id (e.g. "
                        "claude-sonnet-4-6) to draft with Claude — much better "
                        "compile-ready C, but costs API credit and needs "
                        "ANTHROPIC_API_KEY.")
    p.add_argument("--poc-critic-model", default="deepseek-r1:14b",
                   help="Reasoning model for PoC critique (default: deepseek-r1:14b)")
    p.add_argument("--poc-compile-rounds", type=int, default=0, metavar="N",
                   help="compile the generated PoC and feed the errors back to "
                        "the drafter (default 0 = emit-only, never invoke a "
                        "compiler). N is the number of COMPILES, so N-1 repairs: "
                        "N=1 only checks, N=2 checks, repairs and re-checks. "
                        "C uses clang -fsyntax-only against the target headers; "
                        "Java uses javac against the library jars, which it finds "
                        "via POC_JAVA_CP (a folder of jars or a classpath) or in "
                        "the scanned tree's build output. Degrades to emit-only "
                        "when the compiler or the jars/headers are absent. Nothing "
                        "is ever executed.")

    return p.parse_args()


def _target_git_commit(target: Path) -> str | None:
    """Short git commit of the scanned target, if it is a git checkout."""
    try:
        r = subprocess.run(
            ["git", "-C", str(target), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        return r.stdout.strip() or None if r.returncode == 0 else None
    except Exception:
        return None


def _write_run_manifest(outdir: Path, args, context: dict, result, tracker,
                        tel, model: str, run_started: float) -> dict:
    """Write runs/.../run.json — a reproducible record of how this run was
    produced: command, target commit, model/backend, per-stage timings, and
    result counts. Never raises (best-effort)."""
    findings = getattr(result, "findings", []) or []
    confirmed = len([f for f in findings
                     if getattr(getattr(f, "confidence", None), "value", None) == "confirmed"])
    ended = time.time()
    manifest = {
        "command": " ".join(sys.argv),
        "library": args.library,
        "target": str(Path(args.target).resolve()),
        "target_git_commit": _target_git_commit(Path(args.target)),
        "mode": args.mode,
        "phases": args.phases if args.mode == "phases" else None,
        "backend": args.backend,
        "model": model,
        "lang": context.get("lang"),
        "entry_points": len(context.get("entry_points") or []),
        "started": datetime.fromtimestamp(run_started).isoformat(timespec="seconds"),
        "finished": datetime.fromtimestamp(ended).isoformat(timespec="seconds"),
        "duration_seconds": round(ended - run_started, 1),
        "stage_timings": [{"stage": n, "seconds": round(d, 1)}
                          for n, d in getattr(tel, "stage_times", [])],
        "interrupted": bool(getattr(result, "interrupted", False)),
        "findings_total": len(findings),
        "findings_confirmed": confirmed,
        "tokens": {"used": getattr(tracker, "used", None),
                   "budget": getattr(tracker, "budget", None)},
    }
    try:
        (outdir / "run.json").write_text(json.dumps(manifest, indent=2))
    except Exception as e:
        logging.getLogger("pqc").warning("could not write run.json: %s", e)
    return manifest


def _preflight(lang: str, log) -> bool:
    """Log which analysis tools are installed for `lang`. Returns False if a
    REQUIRED tool (rg) is missing. Only reports tools relevant to the language —
    no Go/Java noise on a C/C++ run."""
    from core.tools import tool_status
    rows = tool_status(lang)
    log.info("preflight — analysis tools for lang '%s':", lang)
    ok = True
    for r in rows:
        mark = "OK " if r["installed"] else ("MISSING" if r["required"] else "absent ")
        log.info("  [%s] %-11s %s", mark, r["tool"], r["purpose"])
        if r["required"] and not r["installed"]:
            ok = False
    if not ok:
        log.error("required tool missing — install it before running "
                  "(e.g. `apt install ripgrep` for rg)")
    return ok


def _print_outputs(outdir: Path, manifest: dict) -> None:
    print(f"\nReport:   {outdir / 'report.md'}")
    print(f"JSON:     {outdir / 'report.json'}")
    print(f"Log:      {outdir / 'run.log'}")
    print(f"Manifest: {outdir / 'run.json'}  (took {manifest['duration_seconds']}s)")


def _poc_only(args, log) -> int:
    """`--poc-only <run dir>`: generate PoC packages for a completed run without
    re-scanning. Appends to that run's run.log so the record stays in one place."""
    run_dir = Path(args.poc_only)
    if not run_dir.is_dir():
        log.error("run directory does not exist: %s", run_dir)
        return 2

    # Mirror INFO into the run's own log, the way a scan does.
    try:
        log_fh = open(run_dir / "run.log", "a", encoding="utf-8", buffering=1)
    except OSError:
        log_fh = None
    if log_fh:
        h = logging.StreamHandler(log_fh)
        h.setLevel(logging.INFO)
        h.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logging.getLogger().addHandler(h)

    log.info("poc-only: regenerating PoC packages for %s", run_dir.resolve())
    from pipeline import generate_pocs_for_run
    res = generate_pocs_for_run(
        run_dir,
        drafter_model=args.poc_drafter_model,
        critic_model=args.poc_critic_model,
        compile_rounds=args.poc_compile_rounds,
        overwrite=args.poc_overwrite,
    )
    if res["error"]:
        (log.info if res["ok"] else log.error)("poc-only: %s", res["error"])
    log.info("poc-only: %d generated, %d skipped, %d failed",
             res["generated"], res["skipped"], res["failed"])
    for p in res["packages"]:
        print(f"  {p['id']}: {p['status']}  -> {p['dir']}")
    if log_fh:
        log_fh.close()
    return 0 if res["ok"] else 1


def main() -> int:
    args = build_args()

    console_level = (logging.DEBUG if args.verbose
                     else logging.WARNING if args.quiet else logging.INFO)
    # Root stays at DEBUG so the persisted run.log can keep full INFO detail even
    # when the console is quiet; each handler sets its own level below.
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    for _h in logging.getLogger().handlers:      # the console handler basicConfig made
        _h.setLevel(console_level)
    for noisy in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    log = logging.getLogger("pqc")

    # ---- doctor: report tool availability for this library's language, exit ----
    if args.doctor:
        _spec = config.get_library(args.library)
        _preflight(_spec.lang if _spec else "c", log)
        return 0

    # ---- PoC-only: no scan, just (re)generate packages for a finished run ----
    if args.poc_only:
        return _poc_only(args, log)

    # ---- validate ----
    if not args.target or not args.library:
        log.error("--target and --library are required (omit them only with --poc-only)")
        return 2
    target = Path(args.target)
    if not target.exists():
        log.error("target path does not exist: %s", target)
        return 2

    if args.multi_model and not args.draft_model:
        log.error("--multi-model requires --draft-model")
        return 2

    # ---- output dir + persisted run log (opened before any real work) ----
    outdir = Path(args.outdir) if args.outdir else Path("runs") / args.library / time.strftime("%Y%m%d-%H%M%S")
    outdir.mkdir(parents=True, exist_ok=True)
    # Convenience: runs/<lib>/latest -> newest run dir (skip for custom --outdir).
    if args.outdir is None:
        _link = outdir.parent / "latest"
        try:
            if _link.is_symlink() or _link.exists():
                _link.unlink()
            _link.symlink_to(outdir.name)     # relative target
        except OSError:
            pass  # symlinks may be unavailable on some mounts (e.g. WSL /mnt/c)
    run_started = time.time()
    log_fh = open(outdir / "run.log", "w", encoding="utf-8", buffering=1)
    _file_handler = logging.StreamHandler(log_fh)
    _file_handler.setLevel(logging.INFO)         # run.log is always detailed
    _file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logging.getLogger().addHandler(_file_handler)

    # v3: live progress telemetry — also mirrors an ANSI-stripped copy into run.log
    from core import telemetry
    tel = telemetry.init(
        enabled=getattr(args, "live", True) and not args.quiet,
        sink=log_fh,
    )

    log.info("output dir: %s", outdir.resolve())
    log.info("command: %s", " ".join(sys.argv))

    # Warn about llama3.3-abliterated RAM
    for model_flag in [args.ollama_model, args.draft_model or ""]:
        if "llama3.3-abliterated" in (model_flag or ""):
            log.warning("llama3.3-abliterated (huihui_ai) is a 70B model. "
                        "Requires ~30 GB RAM at Q3_K_M quantisation.")
            break

    # Warn if CIRCL target missing go.mod
    if args.library == "circl":
        if not (target / "go.mod").exists():
            log.warning("No go.mod found in %s — Go static tools may have limited output.", target)

    # ---- token tracker ----
    tracker = TokenTracker(budget=args.token_budget)

    # ---- LLM backend ----
    cfg = LLMConfig()
    if args.cost_saver:
        cfg.model = COST_SAVER_MODEL
    if args.model:
        cfg.model = args.model

    try:
        llm = make_backend(
            args.backend,
            config=cfg,
            ollama_model=args.ollama_model,
            tracker=tracker,
        )
    except Exception as e:
        log.error("LLM backend init failed: %s", e)
        return 2

    log.info("backend: %s", args.backend)
    if args.backend == "anthropic":
        log.info("model: %s (temperature %.1f)", cfg.model, cfg.temperature)

    # Build draft backend for reviewer/resolution in multi-model mode
    draft_llm = llm
    if args.multi_model:
        try:
            draft_llm = make_backend(
                "ollama",
                ollama_model=args.draft_model,
                tracker=tracker,
            )
            log.info("multi-model: investigator=%s, reviewer/resolution=%s",
                     args.backend, args.draft_model)
        except Exception as e:
            log.error("Draft backend init failed: %s", e)
            return 2

    # Build an INDEPENDENT reviewer backend (C3) when requested. A reviewer from
    # a different model family than the investigator is a genuine second opinion
    # rather than a second pass of the same model. Must follow args.backend, not
    # hardcode "ollama" -- the web UI's reviewer-model dropdown is populated from
    # the SAME backend-check call as the investigator's model dropdown (see
    # web/static/app.js), so an Anthropic run with a reviewer model picked from
    # that dropdown was building an OllamaBackend for an Anthropic model name and
    # failing every single review with an HTTP error, silently downgrading every
    # finding to "suspected" instead of a real confirm/dispute verdict.
    reviewer_llm = None
    if args.reviewer_model:
        try:
            if args.backend == "anthropic":
                reviewer_llm = make_backend(
                    "anthropic",
                    config=LLMConfig(model=args.reviewer_model),
                    tracker=tracker,
                )
            else:
                reviewer_llm = make_backend(
                    "ollama",
                    ollama_model=args.reviewer_model,
                    tracker=tracker,
                )
            log.info("independent reviewer model: %s (%s backend)",
                     args.reviewer_model, args.backend)
        except Exception as e:
            log.error("Reviewer backend init failed: %s", e)
            return 2

    spec = config.get_library(args.library)
    lang = spec.lang if spec else "c"
    if not _preflight(lang, log):
        return 2
    if spec is None:
        log.warning("library '%s' has no curated entry points — running "
                    "DISCOVERY-ONLY: symbol enumeration (discover_symbols) "
                    "drives the hunt. Supported, but for best results add a "
                    "libraries/%s.toml with an entry_points list to anchor on "
                    "specific functions.", args.library, args.library)
    context = {
        "target": str(target),
        "library": args.library,
        "lang": lang,
        "entry_points": spec.entry_points if spec else [],
        "globs": spec.globs if spec else config.globs_for(args.library),
        "build_flags": args.build_flags,
        "valgrind_binary": args.valgrind_binary,
        "max_turns": args.max_turns,
        "backend": args.backend,   # drives the backend-aware evidence budget
        "cache_system": (args.backend == "anthropic"),   # prompt caching only for Anthropic
        "cache_reads": args.cache_reads,
        "browse_loop": getattr(args, "browse_loop", False),
        "explain": getattr(args, "explain", False),
    }

    # ---- researcher modes ----
    if args.mode != "phases":
        from pipeline import run_researcher_pipeline
        log.info("mode: %s", args.mode)
        result = run_researcher_pipeline(
            args.mode, llm, outdir, context,
            draft_llm=draft_llm,
            reviewer_llm=reviewer_llm,
            compare_models=[m.strip() for m in args.compare_models.split(",")]
                           if args.compare_models else None,
            cache_reads=args.cache_reads,
            tracker=tracker,
            poc=args.poc,
            poc_drafter_model=args.poc_drafter_model,
            poc_critic_model=args.poc_critic_model,
            poc_compile_rounds=args.poc_compile_rounds,
        )
        manifest = _write_run_manifest(outdir, args, context, result, tracker,
                                       tel, cfg.model, run_started)
        _print_outputs(outdir, manifest)
        print(f"\n{tracker.display()}")
        if getattr(result, "interrupted", False):
            return 130
        if tracker.halted:
            return 2
        return 0

    # ---- phase pipeline (tool-led, default) ----
    agents = {
        Phase.STATIC: StaticAnalysisAgent(llm, outdir / "static"),
        Phase.FUZZING: FuzzingAgent(llm, outdir / "fuzzing", run_seconds=args.fuzz_seconds),
        Phase.DIFFERENTIAL: DifferentialAgent(llm, outdir / "differential"),
        Phase.TIMING: TimingAgent(llm, outdir / "timing", repeats=args.timing_repeats),
        Phase.REPRODUCTION: ReproductionAgent(llm, outdir / "reproduction"),
        Phase.REPORT: ReportAgent(llm, outdir),
    }
    orch = OrchestratorAgent(llm, outdir, agents)
    result = AssessmentResult(target=str(target.resolve()), library=args.library)
    requested = parse_phases(args.phases)
    log.info("requested phases: %s", ", ".join(sorted(p.value for p in requested)))
    try:
        orch.run(result, requested, context)
    except KeyboardInterrupt:
        setattr(result, "interrupted", True)
        log.warning("interrupted by user (Ctrl-C) — writing partial results")
        try:
            agents[Phase.REPORT].run(result, context)
        except Exception as e:
            log.warning("could not write partial report: %s", e)

    manifest = _write_run_manifest(outdir, args, context, result, tracker,
                                   tel, cfg.model, run_started)
    _print_outputs(outdir, manifest)
    print(f"\n{tracker.display()}")
    return 130 if getattr(result, "interrupted", False) else 0


if __name__ == "__main__":
    sys.exit(main())
