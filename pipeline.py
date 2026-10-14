"""Researcher-pipeline driver: agent/reason/agent-review/interactive modes.

v2 additions (all kwargs with defaults so v1 callers work unchanged):
  - draft_llm      : separate backend for reviewer/resolution (multi-model)
  - cache_reads    : per-run tool output cache
  - tracker        : TokenTracker for budget enforcement
  - poc            : enable PoC generation
  - poc_drafter_model, poc_critic_model : models for PoC workflow
"""
from __future__ import annotations

import logging
from pathlib import Path

from core import AssessmentResult, Confidence
from core.llm import TokenTracker
from agents.researcher import ResearcherAgent
from agents.reviewer import ReviewerAgent
from agents.resolution import ResolutionAgent
from agents.report import ReportAgent

log = logging.getLogger("pqc")


def run_researcher_pipeline(
    mode: str,
    llm,
    outdir,
    context: dict,
    # v2 kwargs — all optional so v1 callers keep working
    draft_llm=None,
    reviewer_llm=None,
    cache_reads: bool = False,
    tracker: TokenTracker | None = None,
    poc: bool = False,
    poc_drafter_model: str = "DeepHat/DeepHat-V1-7B",
    poc_critic_model: str = "deepseek-r1:14b",
    poc_compile_rounds: int = 0,
    compare_models: list[str] | None = None,
) -> AssessmentResult:
    result = AssessmentResult(target=context["target"], library=context["library"])

    from core import telemetry as _tlm
    _tel = _tlm.get()
    if _tel:
        _tel.stage("Investigation", f"{context['library']} @ {context['target']}")

    # Ensure v1 callers that don't pass lang/globs still work
    import config as _cfg
    if "lang" not in context:
        context["lang"] = _cfg.LIBRARY_LANG.get(context.get("library", "wolfssl"), "c")
    if "globs" not in context:
        context["globs"] = _cfg.globs_for(context.get("library", "wolfssl"))

    # Tool output cache (v2)
    tool_cache = None
    if cache_reads:
        from core.llm import _extract_json  # noqa — just checking import works
        from core.cache import ToolCache
        tool_cache = ToolCache(enabled=True)
        context["tool_cache"] = tool_cache

    # Reviewer independence (C3): a reviewer that is the SAME model as the
    # investigator shares its blind spots — "two passes of one model" is not an
    # independent check. Prefer an explicit reviewer model, then a draft model,
    # then fall back to the investigator (with a warning that independence is
    # reduced).
    reviewer_llm = reviewer_llm or draft_llm or llm
    resolution_llm = draft_llm or reviewer_llm or llm
    # Only warn when a reviewer actually runs: "reason"/"agent" modes never
    # invoke the ReviewerAgent (see the mode branch below), so the same-model
    # caveat is irrelevant there and the warning is just noise.
    if mode in ("agent-review", "interactive"):
        _inv_model = getattr(llm, "model", None)
        _rev_model = getattr(reviewer_llm, "model", None)
        if _inv_model and _rev_model and _inv_model == _rev_model:
            log.warning("reviewer uses the SAME model as the investigator (%s) — "
                        "verdicts are two passes of one model, not an independent "
                        "check. Pass --reviewer-model with a different model family "
                        "for genuine independence.", _inv_model)

    use_tools = mode != "reason"
    investigator = ResearcherAgent(
        llm, outdir / "investigator",
        use_tools=use_tools,
        max_turns=context.get("max_turns", 16),
    )
    # Ctrl-C at any point below still writes a PARTIAL report from whatever
    # findings were gathered, instead of dumping a traceback and losing the run.
    try:
        if compare_models:
            log.info("compare mode: A/B discovery over models %s", compare_models)
            findings = investigator.run_compare(result, context, compare_models)
        else:
            # direct_extract=True: skip the multi-turn browse loop (unreliable for
            # reasoning models) and go straight to the deterministic gather path.
            # Callers can set context["browse_loop"]=True to re-enable the loop.
            direct = not context.get("browse_loop", False)
            findings = investigator.run(result, context, direct_extract=direct)

        if mode in ("agent", "reason"):
            pass

        elif mode == "agent-review":
            if _tel:
                _tel.stage("Review", f"verifying {len(findings)} finding(s) against source")
            reviewer = ReviewerAgent(reviewer_llm, outdir / "reviewer")
            reviewer.run(result, findings, context=context)
            _resolve_and_log(result, findings, resolution_llm, outdir, context)

        elif mode == "interactive":
            proceed, kept, guidance = _interactive_checkpoint(findings)
            if not proceed:
                log.info("operator aborted before review")
            else:
                if len(kept) < len(findings):
                    for f in findings:
                        if f not in kept:
                            f.add_evidence("operator", "rejected at checkpoint; excluded from review")
                ReviewerAgent(reviewer_llm, outdir / "reviewer").run(result, kept, guidance=guidance, context=context)
                _resolve_and_log(result, kept, resolution_llm, outdir, context)
        else:
            raise SystemExit(f"unknown researcher mode: {mode}")

        # v2: PoC generation for confirmed findings
        if poc:
            _generate_pocs(result, context, poc_drafter_model, poc_critic_model, outdir,
                           compile_rounds=poc_compile_rounds)
    except KeyboardInterrupt:
        setattr(result, "interrupted", True)
        log.warning("interrupted by user (Ctrl-C) — writing a PARTIAL report with "
                    "%d finding(s) gathered so far", len(result.findings))
        if _tel:
            _tel.note("interrupted — writing partial report")

    if _tel:
        _tel.stage("Report", "writing enriched disclosure report")
    ReportAgent(llm, outdir).run(result, context)
    if _tel:
        conf = len([f for f in result.findings if f.confidence.value == "confirmed"])
        _tel.done(f"{len(result.findings)} finding(s) · {conf} confirmed · report in {outdir}")

    if tool_cache:
        log.info(tool_cache.stats())

    if tracker:
        log.info(tracker.display())

    return result


def _finding_to_dict(f) -> dict:
    """Flatten a Finding (+ its reviewer evidence) into the dict the PoC
    generator consumes."""
    def _ev(tag: str) -> str:
        prefix = f"[{tag}]"
        for e in f.evidence:
            if e.startswith(prefix):
                return e.split("]", 1)[-1].strip()
        return ""
    return {
        "id": f.id,
        "title": f.title,
        "cwe": f.cwe or "",
        "severity": f.severity.name,
        "spec_reference": f.spec_reference or "",
        "entry_point": f.entry_point or "",
        "file": f.file or "",
        "line": f.line if f.line is not None else "",
        "description": f.description or "",
        "proving_line": _ev("proving_line"),
        "claim_justification": _ev("claim_justification"),
        "evidence_quote": _ev("evidence_quote"),
        "proposed_fix": _ev("proposed_fix") or _ev("review_fix"),
    }


def _poc_backend(model_id: str):
    """Backend for a PoC model id: a `claude-*` id routes to the Anthropic
    backend (Claude is far better at compile-ready C — opt-in, costs API credit
    and needs ANTHROPIC_API_KEY); anything else stays on local Ollama."""
    from core.llm import make_backend, LLMConfig
    if model_id.startswith("claude-"):
        return make_backend("anthropic", config=LLMConfig(model=model_id))
    return make_backend("ollama", ollama_model=model_id)


def _generate_pocs(result, context, drafter_model, critic_model, outdir,
                   compile_rounds: int = 0) -> None:
    """Generate a documented PoC PACKAGE (code + README + build.sh) per confirmed
    finding for the USER to build and run. The assessor does not compile or run."""
    from poc.generator import generate_poc_package

    confirmed = [f for f in result.findings if f.confidence == Confidence.CONFIRMED]
    if not confirmed:
        log.info("poc: no confirmed findings — skipping PoC generation")
        return

    log.info("poc: generating PoC package(s) for %d confirmed finding(s)", len(confirmed))
    lang = context.get("lang", "c")
    library = context.get("library", "")

    # Build the two backends INDEPENDENTLY. They are often different providers
    # (Claude drafter + local critic is the common pairing), and a failure on one
    # must not discard a working other — losing a usable drafter to an unreachable
    # critic used to throw away the whole stage after a full scan had been paid for.
    def _try_backend(role: str, model_id: str):
        try:
            return _poc_backend(model_id), ""
        except Exception as e:
            return None, str(e).splitlines()[0]

    drafter, drafter_err = _try_backend("drafter", drafter_model)
    critic, critic_err = _try_backend("critic", critic_model)

    if drafter is None and critic is None:
        log.warning("poc: could not initialise either PoC backend — drafter %s: %s; "
                    "critic %s: %s (for Claude set ANTHROPIC_API_KEY; for a local "
                    "model start Ollama)", drafter_model, drafter_err,
                    critic_model, critic_err)
        return
    if drafter is None:
        log.warning("poc: drafter %s unavailable (%s) — drafting with the critic "
                    "model %s instead", drafter_model, drafter_err, critic_model)
        drafter = critic
    elif critic is None:
        log.warning("poc: critic %s unavailable (%s) — continuing with the drafter "
                    "%s alone (no second-model fallback)", critic_model, critic_err,
                    drafter_model)
        critic = drafter
    if drafter_model.startswith("claude-"):
        log.info("poc: drafting with Claude (%s) — billed to ANTHROPIC_API_KEY",
                 drafter_model)

    poc_dir = Path(outdir) / "poc"
    for f in confirmed:
        try:
            res = generate_poc_package(
                finding=_finding_to_dict(f),
                language=lang,
                drafter_backend=drafter,
                critic_backend=critic,
                output_dir=str(poc_dir),
                target_path=context.get("target", ""),
                library=library,
                compile_rounds=compile_rounds,
            )
            _c = res.get("compiled")
            _cnote = {True: " [compiles]", False: " [compile errors remain]"}.get(
                _c, "")
            f.add_evidence("poc",
                           f"PoC package {res['status']}{_cnote}: {res['poc_dir']}")
            f.artifacts.append(res["poc_dir"])
            log.info("poc: %s → %s (%s)", f.id, res["status"], res["poc_dir"])
        except Exception as e:
            log.warning("poc: generation failed for %s: %s", f.id, e)
            f.add_evidence("poc", f"[poc_failed] {e}")


def _report_finding_to_dict(d: dict) -> dict:
    """Same shape as _finding_to_dict, but built from a report.json finding.

    report.json persists everything the generator needs, including the
    `[tag] text` evidence strings, so a finished run can be re-processed without
    re-scanning.
    """
    def _ev(tag: str) -> str:
        prefix = f"[{tag}]"
        for e in d.get("evidence") or []:
            if isinstance(e, str) and e.startswith(prefix):
                return e.split("]", 1)[-1].strip()
        return ""
    return {
        "id": d.get("id", ""),
        "title": d.get("title", ""),
        "cwe": d.get("cwe") or "",
        "severity": (d.get("severity") or "").upper(),
        "spec_reference": d.get("spec_reference") or "",
        "entry_point": d.get("entry_point") or "",
        "file": d.get("file") or "",
        "line": d.get("line") if d.get("line") is not None else "",
        "description": d.get("description") or "",
        "proving_line": _ev("proving_line"),
        "claim_justification": _ev("claim_justification"),
        "evidence_quote": _ev("evidence_quote"),
        "proposed_fix": _ev("proposed_fix") or _ev("review_fix"),
    }


def generate_pocs_for_run(run_dir, drafter_model: str, critic_model: str,
                          compile_rounds: int = 0, overwrite: bool = True,
                          only_ids: list[str] | None = None) -> dict:
    """Generate PoC packages for an ALREADY-COMPLETED run, from its own
    run.json + report.json. Used by `main.py --poc-only` and the web UI's
    "Generate PoCs" action, so no re-scan is needed.

    Returns {ok, generated, skipped, failed, packages, error}.
    """
    import json
    from pathlib import Path as _Path
    from poc.generator import generate_poc_package

    run_dir = _Path(run_dir)
    out = {"ok": False, "generated": 0, "skipped": 0, "failed": 0,
           "packages": [], "error": ""}

    def _read(name):
        p = run_dir / name
        if not p.is_file():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            out["error"] = f"could not read {name}: {e}"
            return None

    manifest = _read("run.json")
    report = _read("report.json")
    if manifest is None or report is None:
        out["error"] = out["error"] or "run.json / report.json missing — not a completed run"
        return out

    target = manifest.get("target") or ""
    library = manifest.get("library") or ""
    lang = manifest.get("lang") or "c"
    if not target or not _Path(target).is_dir():
        # The scanned tree is usually a clone under web/workspaces/, which the
        # UI's "clear runs & clones" deletes. The generator reads real source for
        # API context, so there is nothing honest to do without it.
        out["error"] = (f"the scanned source tree is no longer on disk ({target or 'not recorded'}). "
                        "Re-clone it to that path, or re-run the scan, then try again.")
        return out

    confirmed = [f for f in (report.get("findings") or [])
                 if (f.get("confidence") or "").lower() == "confirmed"]
    if only_ids:
        wanted = set(only_ids)
        confirmed = [f for f in confirmed if f.get("id") in wanted]
    if not confirmed:
        out["ok"] = True
        out["error"] = "no confirmed findings in this run — nothing to generate"
        return out

    drafter, drafter_err = None, ""
    critic, critic_err = None, ""
    try:
        drafter = _poc_backend(drafter_model)
    except Exception as e:
        drafter_err = str(e).splitlines()[0]
    try:
        critic = _poc_backend(critic_model)
    except Exception as e:
        critic_err = str(e).splitlines()[0]
    if drafter is None and critic is None:
        out["error"] = (f"no usable PoC backend — drafter {drafter_model}: {drafter_err}; "
                        f"critic {critic_model}: {critic_err}")
        return out
    drafter = drafter or critic
    critic = critic or drafter

    poc_dir = run_dir / "poc"
    for d in confirmed:
        fid = d.get("id") or "?"
        pkg_dir = poc_dir / fid
        if pkg_dir.exists() and not overwrite:
            log.info("poc: %s already has a package — skipping (overwrite off)", fid)
            out["skipped"] += 1
            continue
        try:
            res = generate_poc_package(
                finding=_report_finding_to_dict(d),
                language=lang,
                drafter_backend=drafter,
                critic_backend=critic,
                output_dir=str(poc_dir),
                target_path=target,
                library=library,
                compile_rounds=compile_rounds,
            )
            out["generated"] += 1
            out["packages"].append({"id": fid, "status": res["status"],
                                    "dir": res["poc_dir"]})
            log.info("poc: %s → %s (%s)", fid, res["status"], res["poc_dir"])
        except Exception as e:
            out["failed"] += 1
            log.warning("poc: generation failed for %s: %s", fid, e)
    out["ok"] = out["generated"] > 0 or out["skipped"] > 0
    return out


def _resolve_and_log(result, findings, llm, outdir, context):
    needs = [f for f in findings
             if f.confidence == Confidence.SUSPECTED
             and any("needs-evidence" in e for e in f.evidence)]
    if not needs:
        log.info("resolution: no needs-evidence findings — skipping")
        return
    log.info("resolution: %d finding(s) need evidence — resolving automatically", len(needs))
    ResolutionAgent(llm, outdir / "resolution").run(result, context)
    now_confirmed = sum(1 for f in needs if f.confidence == Confidence.CONFIRMED)
    now_disputed = sum(1 for f in needs if f.title.startswith("[DISPUTED]"))
    still_needs = sum(1 for f in needs
                      if f.confidence == Confidence.SUSPECTED
                      and any("needs-evidence" in e for e in f.evidence))
    log.info("resolution: %d confirmed, %d disputed, %d still needs-evidence",
             now_confirmed, now_disputed, still_needs)


def _interactive_checkpoint(findings):
    print("\n" + "=" * 70)
    print(f"INVESTIGATOR FINISHED — {len(findings)} finding(s) before review")
    print("=" * 70)
    if not findings:
        print("No findings to review.")
        return True, [], ""
    for i, f in enumerate(findings, 1):
        tgt = f" [maps to {f.matched_target}]" if f.matched_target else ""
        print(f"\n[{i}] ({f.severity.name}){tgt} {f.title}")
        loc = f"{f.file}:{f.line}" if f.file else "(no location)"
        print(f"    {loc}  cwe={f.cwe}  spec={f.spec_reference}")
        desc = (f.description or "").strip().replace("\n", " ")
        print(f"    {desc[:220]}")
    print("\n" + "-" * 70)
    print("Triage: enter finding numbers to KEEP (comma-separated),")
    print("        'all' to keep everything, 'none'/'abort' to stop.")
    sel = input("keep> ").strip().lower()
    if sel in ("none", "abort", "q", "quit"):
        return False, [], ""
    if sel in ("", "all"):
        kept = list(findings)
    else:
        idxs = set()
        for tok in sel.replace(" ", "").split(","):
            if tok.isdigit() and 1 <= int(tok) <= len(findings):
                idxs.add(int(tok))
        kept = [f for i, f in enumerate(findings, 1) if i in idxs]
        if not kept:
            print("(nothing selected — keeping all)")
            kept = list(findings)
    print("\nGuidance for the reviewer (binding instruction it must follow).")
    print("Leave blank for none.")
    guidance = input("guidance> ").strip()
    print(f"\nProceeding to review: {len(kept)} finding(s)"
          + (f", guidance set." if guidance else ", no guidance.") + "\n")
    return True, kept, guidance
