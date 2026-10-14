"""ReportAgent — JSON + HTML + Markdown disclosure output.

Produces three files:
  * report.json  — machine-readable (unchanged)
  * report.html  — styled disclosure report with severity badges, phase
                   indicators, collapsible evidence, and a summary dashboard
  * report.md    — plain markdown fallback (unchanged structure, cleaner prose)

HTML report features:
  - Colour-coded severity badges (CRITICAL=red, HIGH=orange, MEDIUM=yellow,
    LOW=blue, INFO=grey)
  - Phase badges (static / fuzzing / timing / differential / reproduction)
  - Confidence indicator
  - Collapsible evidence sections (click to expand)
  - Summary dashboard: severity breakdown + phase breakdown
  - Validation status table with pass/fail colours
  - CVSS score display
  - Proposed fix section extracted from evidence
  - Replication steps section extracted from evidence
  - All phases represented: works for both researcher pipeline and phase pipeline
"""
from __future__ import annotations

import html
import logging
import re
import time
from pathlib import Path

from agents.base import Agent
from core import AssessmentResult, Finding, Phase, Severity, Confidence

log = logging.getLogger("pqc")

# Severity colour palette
_SEV_COLOURS = {
    Severity.CRITICAL: ("#c0392b", "#fadbd8"),
    Severity.HIGH:     ("#e67e22", "#fdebd0"),
    Severity.MEDIUM:   ("#d4ac0d", "#fef9e7"),
    Severity.LOW:      ("#2980b9", "#d6eaf8"),
    Severity.INFO:     ("#7f8c8d", "#eaecee"),
}

_PHASE_COLOURS = {
    Phase.STATIC:        ("#6c3483", "#e8daef"),
    Phase.FUZZING:       ("#1a5276", "#d6eaf8"),
    Phase.TIMING:        ("#0e6655", "#d1f2eb"),
    Phase.DIFFERENTIAL:  ("#784212", "#fdebd0"),
    Phase.REPRODUCTION:  ("#922b21", "#fadbd8"),
    Phase.REPORT:        ("#7f8c8d", "#eaecee"),
}

_CONF_ICON = {
    Confidence.CONFIRMED:         "✓ Confirmed",
    Confidence.LIKELY:            "~ Likely",
    Confidence.SUSPECTED:         "? Suspected",
    Confidence.EXPECTED_BEHAVIOUR:"✓ Expected behaviour",
}

# Human-readable labels for the discovery-pass surface names (config.discovery_passes()).
# Kept local so the report has no import dependency on agents.researcher._FOCUS_PASSES.
_SURFACE_LABELS = {
    "kem":      "KEM decapsulation / encapsulation / keygen",
    "sig":      "signature sign / verify",
    "sampling": "sampling / RNG / encoding / modular reduction",
    "pki":      "PKI / provider layer",
    "all":      "combined single-pass discovery",
}


class ReportAgent(Agent):
    required_tools = ()

    def run(self, result: AssessmentResult, context: dict) -> list[Finding]:
        out = self.workdir
        # v3: enrich findings with analytical narratives before rendering, so
        # the report reads like an expert write-up rather than raw fields.
        if getattr(self, "llm", None) is not None and result.findings:
            self._enrich_findings(result, context)
        (out / "report.json").write_text(result.to_json(), encoding="utf-8")
        (out / "report.md").write_text(self._markdown(result), encoding="utf-8")
        (out / "report.html").write_text(self._html(result), encoding="utf-8")
        log.info("report written: %s", out / "report.html")
        return []

    # ------------------------------------------------------------------
    # v3: narrative enrichment
    # ------------------------------------------------------------------

    def _enrich_findings(self, result: AssessmentResult, context: dict) -> None:
        """Generate a rich analytical narrative for each finding: technical
        impact, attack scenario, severity rationale, detailed remediation, and
        references. Stored on the finding so HTML/MD can render it."""
        enrich_system = (
            "You are a senior cryptographic security analyst writing a "
            "responsible-disclosure report for a vendor security team. For the "
            "finding given, write a thorough, technically precise analysis. "
            "Be concrete and reference the specific function and mechanism. "
            "Do not invent code you weren't shown. Output ONLY valid JSON:\n"
            "{\n"
            '  "technical_summary": "2-3 sentence precise technical description",\n'
            '  "impact": "what an attacker gains; concrete consequences",\n'
            '  "attack_scenario": "step-by-step how this would be exploited in practice",\n'
            '  "severity_rationale": "why this severity; reference CVSS-style reasoning",\n'
            '  "remediation": "specific, actionable fix with the exact mechanism to add",\n'
            '  "references": ["relevant FIPS section, CWE, CVE, or paper names"]\n'
            "}"
        )
        for f in result.findings:
            # v3: do not write a confident exploit narrative for findings the
            # review/resolution stage DISPUTED. Dressing up a rejected finding
            # as real undermines the whole report. Mark them honestly instead.
            title_l = f.title.lower()
            is_disputed = (f.title.startswith("[DISPUTED]")
                           or "disputed" in title_l
                           or any("verdict=disputed" in e.lower()
                                  or "-> disputed" in e.lower()
                                  or "resolution] disputed" in e.lower()
                                  for e in f.evidence))
            if is_disputed:
                f.enrichment = {
                    "technical_summary": (
                        "This finding was DISPUTED during automated review — the "
                        "reviewing agent inspected the cited code and did not find "
                        "the claimed vulnerability. It is retained for "
                        "transparency but is most likely a false positive."),
                }
                log.debug("enrichment: finding %s disputed — flagged not enriched", f.id)
                continue
            # Performance: the enrichment LLM call is the heavy investigator
            # model run once PER finding, serially, at the end of every run — a
            # large chunk of wall-time on local models. Only CONFIRMED findings
            # get the full narrative; unconfirmed leads still RENDER (with all
            # their fields) but get a cheap, non-LLM note instead of a call.
            if f.confidence != Confidence.CONFIRMED:
                f.enrichment = {
                    "technical_summary": (
                        f"Unconfirmed lead (confidence: {f.confidence.value}). The "
                        "reviewer did not confirm this finding; it is retained as a "
                        "lead. Inspect the evidence and verify manually before "
                        "acting on it."),
                }
                log.debug("enrichment: %s not confirmed (%s) — light note, no LLM",
                          f.id, f.confidence.value)
                continue
            ev = "\n".join(f.evidence)
            user = (
                f"Library: {result.library}\n"
                f"Finding: {f.title}\n"
                f"Severity: {f.severity.name}\nCWE: {f.cwe}\n"
                f"Location: {f.file}:{f.line}\n"
                f"Spec: {f.spec_reference}\n"
                f"Description: {f.description}\n\n"
                f"Evidence:\n{ev[:2000]}\n\n"
                "Write the disclosure analysis JSON."
            )
            try:
                from core.llm import _extract_json
                raw = self.llm.complete(enrich_system, user, max_tokens=2048,
                                        temperature=0.2)
                data = _extract_json(raw)
                if isinstance(data, dict):
                    f.enrichment = data
                    log.debug("enriched finding %s", f.id)
            except Exception as e:
                log.debug("enrichment failed for %s: %s", f.id, e)
                f.enrichment = None

    # ------------------------------------------------------------------
    # HTML report
    # ------------------------------------------------------------------

    def _html(self, r: AssessmentResult) -> str:
        vs = r.validation_status()
        dur = (r.finished - r.started) if r.finished else 0
        ordered = sorted(r.findings,
                         key=lambda f: (-int(f.severity), f.phase.value))

        # Phase breakdown
        phase_counts: dict[str, int] = {}
        for f in r.findings:
            phase_counts[f.phase.value] = phase_counts.get(f.phase.value, 0) + 1

        sev_counts = {sev: len([f for f in r.findings if f.severity == sev])
                      for sev in reversed(list(Severity))}

        val_colour = "#27ae60" if vs["all_rediscovered"] else "#e74c3c"
        val_label  = "PASS" if vs["all_rediscovered"] else "INCOMPLETE"

        # Validation card only shown for libraries with known ground-truth.
        if vs.get("has_targets", True) and vs["total_targets"] > 0:
            validation_card = f"""
    <div class="card validation" style="border-left: 4px solid {val_colour}">
      <div class="card-title">Validation</div>
      <div class="card-value" style="color:{val_colour}">{val_label}</div>
      <div class="card-sub">
        {vs['rediscovered']}/{vs['total_targets']} manual targets rediscovered
      </div>
    </div>"""
        else:
            validation_card = ""

        parts = [self._html_head(r.library)]
        parts.append(f"""
<body>
<div class="container">
  <header>
    <h1>PQC Security Assessment</h1>
    <div class="subtitle">
      <span class="library-badge">{html.escape(r.library.upper())}</span>
      <code>{html.escape(r.target)}</code>
    </div>
    <div class="meta">
      {len(r.findings)} finding(s) &nbsp;·&nbsp; Runtime: {dur:.1f}s
      &nbsp;·&nbsp; {time.strftime('%Y-%m-%d %H:%M', time.localtime(r.started))}
    </div>
  </header>

  <section class="dashboard">
    {validation_card}
    {self._severity_cards(sev_counts)}
    {self._phase_card(phase_counts)}
  </section>

  {self._coverage_section(r)}
  {self._validation_table(vs)}
  {self._findings_section(ordered)}
</div>
</body></html>""")
        return "\n".join(parts)

    def _html_head(self, library: str) -> str:
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PQC Assessment — {html.escape(library)}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: #f4f6f9; color: #2c3e50; line-height: 1.6; }}
    .container {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
    header {{ background: #1a252f; color: #ecf0f1; border-radius: 8px;
              padding: 28px 32px; margin-bottom: 24px; }}
    header h1 {{ font-size: 1.8rem; font-weight: 700; }}
    .subtitle {{ margin-top: 8px; opacity: 0.85; }}
    .library-badge {{ background: #3498db; color: white; border-radius: 4px;
                      padding: 2px 10px; font-size: 0.8rem; font-weight: 700;
                      letter-spacing: 1px; margin-right: 10px; }}
    .meta {{ margin-top: 8px; font-size: 0.85rem; opacity: 0.7; }}
    .dashboard {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }}
    .card {{ background: white; border-radius: 8px; padding: 16px 20px;
             box-shadow: 0 1px 4px rgba(0,0,0,.08); flex: 1; min-width: 140px; }}
    .card-title {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px;
                   color: #7f8c8d; font-weight: 600; }}
    .card-value {{ font-size: 2rem; font-weight: 700; margin: 4px 0; }}
    .card-sub {{ font-size: 0.8rem; color: #7f8c8d; }}
    .sev-row {{ display: flex; align-items: center; gap: 8px; margin: 3px 0; }}
    section.validation, section.findings, section.coverage {{ background: white; border-radius: 8px;
      padding: 24px; margin-bottom: 24px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
    h2 {{ font-size: 1.2rem; margin-bottom: 16px; color: #2c3e50; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
    th {{ background: #f4f6f9; text-align: left; padding: 10px 14px;
          font-weight: 600; border-bottom: 2px solid #dee2e6; }}
    td {{ padding: 10px 14px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }}
    .badge {{ display: inline-block; padding: 2px 10px; border-radius: 20px;
              font-size: 0.75rem; font-weight: 700; letter-spacing: 0.5px; }}
    .finding-card {{ border: 1px solid #e8ecef; border-radius: 8px;
                     margin-bottom: 16px; overflow: hidden; }}
    .finding-header {{ padding: 14px 18px; cursor: pointer;
                       display: flex; align-items: flex-start; gap: 12px; }}
    .finding-header:hover {{ filter: brightness(0.97); }}
    .finding-title {{ font-weight: 600; font-size: 0.95rem; flex: 1; }}
    .finding-loc {{ font-size: 0.8rem; color: #7f8c8d; margin-top: 2px;
                    font-family: monospace; }}
    .finding-body {{ padding: 0 18px 18px; border-top: 1px solid #e8ecef; }}
    .meta-row {{ display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0; }}
    .meta-pill {{ background: #f4f6f9; border-radius: 4px; padding: 3px 10px;
                  font-size: 0.8rem; color: #555; }}
    .meta-pill code {{ font-size: 0.8rem; }}
    .section-label {{ font-size: 0.75rem; text-transform: uppercase; font-weight: 700;
                      letter-spacing: 1px; color: #7f8c8d; margin: 14px 0 6px; }}
    .description {{ font-size: 0.9rem; color: #34495e; }}
    details {{ margin: 12px 0; }}
    details summary {{ cursor: pointer; font-size: 0.85rem; color: #3498db;
                       font-weight: 600; user-select: none; }}
    details summary:hover {{ text-decoration: underline; }}
    pre {{ background: #1e2933; color: #cdd3de; border-radius: 6px;
           padding: 14px; font-size: 0.78rem; overflow-x: auto;
           margin-top: 8px; white-space: pre-wrap; word-break: break-all; }}
    .fix-box {{ background: #eafaf1; border-left: 3px solid #27ae60;
                border-radius: 0 6px 6px 0; padding: 10px 14px;
                font-size: 0.88rem; }}
    .repro-box {{ background: #fdfefe; border-left: 3px solid #3498db;
                  border-radius: 0 6px 6px 0; padding: 10px 14px;
                  font-size: 0.88rem; }}
    .artifact-list {{ font-size: 0.85rem; }}
    .artifact-list li {{ font-family: monospace; color: #555; }}
    .pass  {{ color: #27ae60; font-weight: 700; }}
    .fail  {{ color: #e74c3c; font-weight: 700; }}
    .needs {{ color: #e67e22; font-weight: 700; }}
    @media (max-width: 600px) {{
      .dashboard {{ flex-direction: column; }}
      .finding-header {{ flex-direction: column; }}
    }}
  </style>
</head>"""

    def _severity_cards(self, counts: dict) -> str:
        parts = []
        for sev in reversed(list(Severity)):
            n = counts.get(sev, 0)
            if n == 0:
                continue
            fg, bg = _SEV_COLOURS[sev]
            parts.append(f"""
    <div class="card" style="border-left: 4px solid {fg}">
      <div class="card-title">{sev.name}</div>
      <div class="card-value" style="color:{fg}">{n}</div>
      <div class="card-sub">finding(s)</div>
    </div>""")
        return "\n".join(parts)

    def _phase_card(self, counts: dict) -> str:
        if not counts:
            return ""
        rows = "\n".join(
            f'<div class="sev-row">'
            f'<span class="badge" style="background:{_PHASE_COLOURS.get(Phase(p), ("#999","#eee"))[1]};'
            f'color:{_PHASE_COLOURS.get(Phase(p), ("#999","#eee"))[0]}">{p}</span>'
            f'<span>{n}</span></div>'
            for p, n in sorted(counts.items())
        )
        return f"""
    <div class="card">
      <div class="card-title">By Phase</div>
      <div style="margin-top:8px">{rows}</div>
    </div>"""

    def _validation_table(self, vs: dict) -> str:
        # No known ground-truth targets for this library — omit the table.
        if not vs.get("has_targets", True) or vs["total_targets"] == 0:
            return ""
        rows = []
        for tid, info in vs["targets"].items():
            if info["rediscovered"]:
                mark = '<span class="pass">✓ Yes</span>'
            else:
                mark = '<span class="fail">✗ No</span>'
            ids = ", ".join(
                f'<code>{i}</code>' for i in info["finding_ids"]
            ) or "—"
            rows.append(
                f"<tr><td><strong>{html.escape(tid)}</strong></td>"
                f"<td>{html.escape(info['description'])}</td>"
                f"<td>{mark}</td><td>{ids}</td></tr>"
            )
        val_colour = "#27ae60" if vs["all_rediscovered"] else "#e74c3c"
        val_label  = "PASS ✓" if vs["all_rediscovered"] else "INCOMPLETE"
        return f"""
  <section class="validation">
    <h2>Validation Status &nbsp;
      <span style="color:{val_colour};font-size:0.9rem">{val_label}</span>
      <span style="font-size:0.85rem;color:#7f8c8d;font-weight:400">
        &nbsp; {vs['rediscovered']}/{vs['total_targets']} manual targets
      </span>
    </h2>
    <table>
      <thead><tr><th>Target</th><th>Description</th>
        <th>Rediscovered</th><th>Finding IDs</th></tr></thead>
      <tbody>{"".join(rows)}</tbody>
    </table>
  </section>"""

    def _coverage_section(self, r: AssessmentResult) -> str:
        """Scope & coverage: what was actually examined. Makes a clean (0-finding)
        run demonstrate the work done — curated entry points, cryptographic
        surfaces, and an explicit true-negative statement — instead of rendering a
        blank 'No findings.' page that reads as if nothing ran. Fully guarded: a
        config hiccup returns '' rather than crashing the report."""
        try:
            import config as _cfg
            spec = _cfg.get_library(r.library)
            lang = getattr(spec, "lang", None) or "—"
            eps = list(getattr(spec, "entry_points", []) or [])
            pki = list(getattr(spec, "pki_entry_points", []) or [])
            all_eps = eps + [p for p in pki if p not in eps]
            try:
                passes = list(_cfg.discovery_passes(r.library))
            except Exception:
                passes = []

            total = len(r.findings)
            confirmed = sum(1 for f in r.findings
                            if f.confidence == Confidence.CONFIRMED)
            disputed = sum(1 for f in r.findings
                           if (f.title or "").startswith("[DISPUTED]"))

            surf_pills = "".join(
                f'<span class="meta-pill">{html.escape(_SURFACE_LABELS.get(p, p))}</span>'
                for p in passes
            ) or '<span class="meta-pill">default discovery</span>'

            # Level-A: if the run recorded per-entry-point resolution, render a
            # disposition table (examined / cleared / not-found) instead of a flat
            # list. Falls back to the config list when no runtime data is present.
            cov = getattr(r, "coverage", None) or {}
            ep_cov = cov.get("entry_points") or {}
            finding_bases = {(f.file or "").replace("\\", "/").split("/")[-1].lower()
                             for f in r.findings if f.file}
            if ep_cov:
                rows = []
                for ep in all_eps or list(ep_cov):
                    info = ep_cov.get(ep, {"resolved": False, "file": None})
                    if not info.get("resolved"):
                        disp = '<span style="color:#7f8c8d">symbol not found in target</span>'
                        loc = "—"
                    else:
                        loc = html.escape(info.get("file") or "")
                        base = (info.get("file") or "").split(":")[0].split("/")[-1].lower()
                        if base in finding_bases:
                            disp = '<span style="color:#e67e22">flagged — see findings</span>'
                        else:
                            disp = '<span style="color:#27ae60">examined — cleared</span>'
                    rows.append(
                        f"<tr><td><code>{html.escape(ep)}</code></td>"
                        f"<td style='font-family:monospace;font-size:0.8rem'>{loc}</td>"
                        f"<td>{disp}</td></tr>")
                n_res = sum(1 for i in ep_cov.values() if i.get("resolved"))
                ep_block = (
                    f'<div class="section-label" style="margin-top:16px">Entry-point '
                    f'coverage &nbsp;<span style="color:#7f8c8d;font-weight:400">'
                    f'{n_res}/{len(ep_cov)} resolved to source</span></div>'
                    f'<details style="margin-top:6px"><summary>show per-entry-point '
                    f'disposition</summary><table style="margin-top:8px"><thead><tr>'
                    f'<th>Entry point</th><th>Location</th><th>Disposition</th></tr>'
                    f'</thead><tbody>{"".join(rows)}</tbody></table></details>')
            elif all_eps:
                ep_list = ", ".join(
                    f"<code>{html.escape(e)}</code>" for e in all_eps)
                ep_block = (
                    f'<details style="margin-top:12px"><summary>'
                    f'{len(all_eps)} curated entry point(s) examined</summary>'
                    f'<p style="margin-top:8px" class="description">{ep_list}</p>'
                    f'</details>')
            else:
                ep_block = ""

            # Per-pass summary (risky lines each pass flagged for scrutiny).
            pass_rows = ""
            for p in cov.get("passes", []):
                pass_rows += (
                    f'<span class="meta-pill">{html.escape(str(p.get("label","?")))}: '
                    f'{p.get("risky_lines",0)} risky line(s), '
                    f'{p.get("grounded",0)} grounded</span>')
            pass_block = (f'<div class="section-label" style="margin-top:16px">'
                          f'Per-pass triage</div><div class="meta-row">{pass_rows}</div>'
                          if pass_rows else "")

            if total == 0:
                note = (
                    '<p class="description" style="margin-top:14px">'
                    'All examined surfaces were exercised and <strong>no defect '
                    'survived verbatim-evidence grounding</strong>. On a hardened '
                    'target a zero result is a deliberate true-negative — the scan '
                    'ran to completion; it was not skipped or errored.</p>')
            elif confirmed == 0:
                note = (
                    '<p class="description" style="margin-top:14px">'
                    f'{total} lead(s) surfaced but <strong>0 confirmed</strong> '
                    'after independent review and grounding. Unconfirmed leads are '
                    'retained below for manual triage.</p>')
            else:
                note = ""

            disp_pill = (f'<span class="meta-pill">Disputed: {disputed}</span>'
                         if disputed else "")

            return f"""
  <section class="coverage">
    <h2>Scope &amp; Coverage</h2>
    <div class="meta-row">
      <span class="meta-pill">Language: <code>{html.escape(lang)}</code></span>
      <span class="meta-pill">Entry points: {len(all_eps)}</span>
      <span class="meta-pill">Discovery passes: {len(passes) or '—'}</span>
      <span class="meta-pill">Leads: {total}</span>
      <span class="meta-pill">Confirmed: {confirmed}</span>
      {disp_pill}
    </div>
    <div class="section-label">Cryptographic surfaces examined</div>
    <div class="meta-row">{surf_pills}</div>
    {ep_block}
    {pass_block}
    {note}
  </section>{self._triage_section(r)}"""
        except Exception as e:  # never let coverage rendering break a report
            log.debug("coverage section skipped: %s", e)
            return ""

    def _triage_section(self, r: AssessmentResult) -> str:
        """Level-B: the model's 'examined and dismissed' log (--explain). Clearly
        labelled as unverified model commentary — it is NOT a verified verdict."""
        try:
            triage = getattr(r, "triage", None) or []
            if not triage:
                return ""
            rows = "".join(
                f"<tr><td style='font-family:monospace;font-size:0.8rem'>"
                f"{html.escape(str(t.get('location','') or '—'))}</td>"
                f"<td>{html.escape(str(t.get('reason','')))}</td>"
                f"<td style='color:#7f8c8d'>{html.escape(str(t.get('pass','')))}</td>"
                f"</tr>"
                for t in triage[:60])
            return f"""
  <section class="coverage">
    <h2>Triage Log <span style="font-size:0.8rem;color:#7f8c8d;font-weight:400">
      &nbsp;candidates examined and dismissed · model commentary, unverified</span></h2>
    <p class="description" style="margin-bottom:12px">Locations the investigator
      considered and cleared, with its stated reason. This is the model's own
      explanation — it is <strong>not</strong> a grounded verdict, and is shown for
      transparency into what was looked at and why it was set aside.</p>
    <table><thead><tr><th>Location</th><th>Why dismissed</th><th>Pass</th></tr></thead>
      <tbody>{rows}</tbody></table>
  </section>"""
        except Exception as e:
            log.debug("triage section skipped: %s", e)
            return ""

    def _findings_section(self, findings: list[Finding]) -> str:
        if not findings:
            return '<section class="findings"><h2>Findings</h2><p>No findings.</p></section>'
        cards = "\n".join(self._finding_card(f) for f in findings)
        return f'<section class="findings"><h2>Findings</h2>{cards}</section>'

    def _finding_card(self, f: Finding) -> str:
        fg, bg = _SEV_COLOURS.get(f.severity, ("#999", "#eee"))
        pfg, pbg = _PHASE_COLOURS.get(f.phase, ("#999", "#eee"))
        conf_icon = _CONF_ICON.get(f.confidence, f.confidence.value)
        conf_colour = "#27ae60" if f.confidence == Confidence.CONFIRMED else \
                      "#e67e22" if f.confidence == Confidence.LIKELY else \
                      "#e74c3c" if f.confidence == Confidence.SUSPECTED else "#7f8c8d"

        loc_html = ""
        if f.file:
            loc = f"{f.file}:{f.line}" if f.line else f.file
            loc_html = f'<div class="finding-loc">📁 {html.escape(loc)}</div>'

        # Meta pills
        pills = []
        pills.append(f'<span class="meta-pill"><code>{html.escape(f.id)}</code></span>')
        if f.cwe:
            pills.append(f'<span class="meta-pill">🔗 {html.escape(f.cwe)}</span>')
        if f.cvss_vector:
            pills.append(f'<span class="meta-pill">CVSS {f.cvss_score}</span>')
        if f.spec_reference:
            pills.append(f'<span class="meta-pill">📋 {html.escape(f.spec_reference)}</span>')
        if f.matched_target:
            pills.append(f'<span class="meta-pill" style="background:#fdebd0;color:#784212">'
                         f'🎯 {html.escape(f.matched_target)}</span>')
        if f.entry_point:
            pills.append(f'<span class="meta-pill"><code>{html.escape(f.entry_point)}</code></span>')
        if getattr(f, "discovered_by", None):
            pills.append(f'<span class="meta-pill" style="background:#e9f0fc;color:#2d6cdf">'
                         f'🤖 {html.escape(f.discovered_by)}</span>')

        # Extract structured sections from evidence
        fix_text = self._extract_evidence_section(f, "proposed_fix")
        repro_text = self._extract_evidence_section(f, "replication")
        review_text = self._extract_evidence_section(f, "review")
        resolution_text = self._extract_evidence_section(f, "resolution_verdict")

        body_parts = []
        if f.description:
            body_parts.append(
                f'<div class="section-label">Description</div>'
                f'<div class="description">{html.escape(f.description)}</div>'
            )

        # v3: rich analytical narrative (from the enrichment pass)
        enr = getattr(f, "enrichment", None)
        if isinstance(enr, dict):
            if enr.get("technical_summary"):
                body_parts.append(
                    f'<div class="section-label">Technical Analysis</div>'
                    f'<div class="description">{html.escape(str(enr["technical_summary"]))}</div>'
                )
            if enr.get("impact"):
                body_parts.append(
                    f'<div class="section-label">Impact</div>'
                    f'<div class="description">{html.escape(str(enr["impact"]))}</div>'
                )
            if enr.get("attack_scenario"):
                body_parts.append(
                    f'<div class="section-label">Attack Scenario</div>'
                    f'<div class="repro-box">{html.escape(str(enr["attack_scenario"]))}</div>'
                )
            if enr.get("severity_rationale"):
                body_parts.append(
                    f'<div class="section-label">Severity Rationale</div>'
                    f'<div class="description">{html.escape(str(enr["severity_rationale"]))}</div>'
                )
            if enr.get("remediation"):
                body_parts.append(
                    f'<div class="section-label">Remediation</div>'
                    f'<div class="fix-box">{html.escape(str(enr["remediation"]))}</div>'
                )
            refs = enr.get("references")
            if refs and isinstance(refs, list):
                ref_items = "".join(
                    f"<li>{html.escape(str(rf))}</li>" for rf in refs
                )
                body_parts.append(
                    f'<div class="section-label">References</div>'
                    f'<ul class="artifact-list">{ref_items}</ul>'
                )

        if repro_text:
            body_parts.append(
                f'<div class="section-label">Replication</div>'
                f'<div class="repro-box">{html.escape(repro_text)}</div>'
            )
        if fix_text:
            body_parts.append(
                f'<div class="section-label">Proposed Fix</div>'
                f'<div class="fix-box">{html.escape(fix_text)}</div>'
            )
        if review_text or resolution_text:
            rv = resolution_text or review_text
            body_parts.append(
                f'<div class="section-label">Review Verdict</div>'
                f'<div class="description" style="color:{conf_colour}">'
                f'{html.escape(rv[:500])}</div>'
            )
        if f.artifacts:
            items = "".join(f"<li>{html.escape(a)}</li>" for a in f.artifacts)
            body_parts.append(
                f'<div class="section-label">Artifacts</div>'
                f'<ul class="artifact-list">{items}</ul>'
            )

        # Collapsible raw evidence
        raw_ev = [e for e in f.evidence
                  if not any(k in e[:30] for k in
                             ("[proposed_fix]", "[replication]", "[review]",
                              "[resolution_verdict]", "[review_fix]",
                              "[resolution_fix]"))]
        if raw_ev:
            ev_html = "".join(
                f"<pre>{html.escape(e[:2000])}</pre>" for e in raw_ev
            )
            body_parts.append(
                f'<details><summary>Raw evidence ({len(raw_ev)} item(s))</summary>'
                f'{ev_html}</details>'
            )

        return f"""
<div class="finding-card">
  <div class="finding-header" style="background:{bg}">
    <span class="badge" style="background:{fg};color:white;white-space:nowrap">
      {f.severity.name}
    </span>
    <div style="flex:1">
      <div class="finding-title">{html.escape(f.title)}</div>
      {loc_html}
    </div>
    <span class="badge" style="background:{pbg};color:{pfg};white-space:nowrap">
      {f.phase.value}
    </span>
    <span style="font-size:0.8rem;color:{conf_colour};white-space:nowrap">
      {conf_icon}
    </span>
  </div>
  <div class="finding-body">
    <div class="meta-row">{"".join(pills)}</div>
    {"".join(body_parts)}
  </div>
</div>"""

    def _extract_evidence_section(self, f: Finding, key: str) -> str:
        """Pull the content of a named evidence section."""
        for e in f.evidence:
            prefix = f"[{key}] "
            if e.startswith(prefix):
                return e[len(prefix):].strip()
        return ""

    # ------------------------------------------------------------------
    # Markdown report (cleaner prose version)
    # ------------------------------------------------------------------

    def _markdown(self, r: AssessmentResult) -> str:
        vs = r.validation_status()
        dur = (r.finished - r.started) if r.finished else 0
        lines: list[str] = []
        lines.append(f"# PQC Security Assessment — {r.library}")
        lines.append("")
        lines.append(f"**Target:** `{r.target}`  ")
        lines.append(f"**Date:** {time.strftime('%Y-%m-%d %H:%M')}  ")
        lines.append(f"**Findings:** {len(r.findings)}  ·  **Runtime:** {dur:.1f}s")
        lines.append("")

        lines.extend(self._md_coverage(r))

        flag = "✓ PASS" if vs["all_rediscovered"] else "✗ INCOMPLETE"
        lines.append(f"## Validation — {flag}")
        lines.append("")
        lines.append(f"Rediscovered {vs['rediscovered']}/{vs['total_targets']} manual targets.")
        lines.append("")
        lines.append("| Target | Description | Status | Findings |")
        lines.append("|---|---|---|---|")
        for tid, info in vs["targets"].items():
            mark = "✓" if info["rediscovered"] else "✗"
            ids = ", ".join(f"`{i}`" for i in info["finding_ids"]) or "—"
            lines.append(f"| {tid} | {info['description']} | {mark} | {ids} |")
        lines.append("")

        lines.append("## Summary")
        lines.append("")
        for sev in reversed(list(Severity)):
            n = len([f for f in r.findings if f.severity == sev])
            if n:
                lines.append(f"- **{sev.name}**: {n}")

        # Phase breakdown
        phase_counts: dict[str, int] = {}
        for f in r.findings:
            phase_counts[f.phase.value] = phase_counts.get(f.phase.value, 0) + 1
        if phase_counts:
            lines.append("")
            lines.append("**By phase:**")
            for p, n in sorted(phase_counts.items()):
                lines.append(f"- {p}: {n}")
        lines.append("")

        lines.append("## Findings")
        lines.append("")
        ordered = sorted(r.findings, key=lambda f: (-int(f.severity), f.phase.value))
        for f in ordered:
            lines.extend(self._md_finding(f))
        return "\n".join(lines)

    def _md_coverage(self, r: AssessmentResult) -> list[str]:
        """Markdown twin of _coverage_section. Guarded — returns [] on any error."""
        try:
            import config as _cfg
            spec = _cfg.get_library(r.library)
            lang = getattr(spec, "lang", None) or "—"
            eps = list(getattr(spec, "entry_points", []) or [])
            pki = list(getattr(spec, "pki_entry_points", []) or [])
            all_eps = eps + [p for p in pki if p not in eps]
            try:
                passes = list(_cfg.discovery_passes(r.library))
            except Exception:
                passes = []
            total = len(r.findings)
            confirmed = sum(1 for f in r.findings
                            if f.confidence == Confidence.CONFIRMED)

            L = ["## Scope & Coverage", ""]
            L.append(f"- **Language:** {lang}")
            L.append(f"- **Curated entry points examined:** {len(all_eps)}")
            if passes:
                L.append("- **Cryptographic surfaces (discovery passes):** "
                         + ", ".join(_SURFACE_LABELS.get(p, p) for p in passes))
            L.append(f"- **Leads surfaced:** {total}  ·  **Confirmed:** {confirmed}")

            cov = getattr(r, "coverage", None) or {}
            ep_cov = cov.get("entry_points") or {}
            finding_bases = {(f.file or "").replace("\\", "/").split("/")[-1].lower()
                             for f in r.findings if f.file}
            if ep_cov:
                n_res = sum(1 for i in ep_cov.values() if i.get("resolved"))
                L.append("")
                L.append(f"**Entry-point coverage** ({n_res}/{len(ep_cov)} "
                         "resolved to source):")
                L.append("")
                L.append("| Entry point | Location | Disposition |")
                L.append("|---|---|---|")
                for ep in (all_eps or list(ep_cov)):
                    info = ep_cov.get(ep, {"resolved": False, "file": None})
                    if not info.get("resolved"):
                        loc, disp = "—", "symbol not found in target"
                    else:
                        loc = info.get("file") or ""
                        base = loc.split(":")[0].split("/")[-1].lower()
                        disp = ("flagged — see findings" if base in finding_bases
                                else "examined — cleared")
                    L.append(f"| `{ep}` | `{loc}` | {disp} |")
                if cov.get("passes"):
                    L.append("")
                    L.append("**Per-pass triage:** " + "; ".join(
                        f"{p.get('label','?')} — {p.get('risky_lines',0)} risky "
                        f"line(s), {p.get('grounded',0)} grounded"
                        for p in cov["passes"]))
            elif all_eps:
                L.append("")
                L.append("<details><summary>Entry points examined</summary>\n\n"
                         + ", ".join(f"`{e}`" for e in all_eps) + "\n\n</details>")
            L.append("")
            if total == 0:
                L.append("All examined surfaces were exercised and no defect "
                         "survived verbatim-evidence grounding. A zero result on a "
                         "hardened target is a deliberate true-negative — the scan "
                         "ran to completion; it was not skipped or errored.")
            elif confirmed == 0:
                L.append(f"{total} lead(s) surfaced but 0 confirmed after review "
                         "and grounding; leads are retained below for manual triage.")
            L.append("")

            # Level-B triage log (--explain): model's examined-and-dismissed notes.
            triage = getattr(r, "triage", None) or []
            if triage:
                L.append("## Triage Log")
                L.append("")
                L.append("_Candidates the investigator examined and dismissed, with "
                         "its stated reason. Model commentary — unverified, shown for "
                         "transparency, not a grounded verdict._")
                L.append("")
                L.append("| Location | Why dismissed | Pass |")
                L.append("|---|---|---|")
                for t in triage[:60]:
                    loc = str(t.get("location", "") or "—").replace("|", "\\|")
                    why = str(t.get("reason", "")).replace("|", "\\|")
                    L.append(f"| `{loc}` | {why} | {t.get('pass','')} |")
                L.append("")
            return L
        except Exception as e:
            log.debug("md coverage skipped: %s", e)
            return []

    def _md_finding(self, f: Finding) -> list[str]:
        b: list[str] = []
        loc = f" — `{f.file}{':'+str(f.line) if f.line else ''}`" if f.file else ""
        disputed = "~~" if f.title.startswith("[DISPUTED]") else ""
        b.append(f"### [{f.severity.name}] {disputed}{f.title}{disputed}{loc}")
        b.append("")
        meta = [f"`{f.id}`", f.phase.value, f.confidence.value]
        if f.cwe:       meta.append(f.cwe)
        if f.cvss_vector: meta.append(f"CVSS {f.cvss_score}")
        if f.spec_reference: meta.append(f.spec_reference)
        if f.matched_target: meta.append(f"**→ {f.matched_target}**")
        if getattr(f, "discovered_by", None): meta.append(f"model={f.discovered_by}")
        b.append("  ·  ".join(meta))
        b.append("")
        if f.description:
            b.append(f.description)
            b.append("")

        # v3: rich analytical narrative
        enr = getattr(f, "enrichment", None)
        if isinstance(enr, dict):
            if enr.get("technical_summary"):
                b.append(f"**Technical Analysis:** {enr['technical_summary']}")
                b.append("")
            if enr.get("impact"):
                b.append(f"**Impact:** {enr['impact']}")
                b.append("")
            if enr.get("attack_scenario"):
                b.append(f"**Attack Scenario:** {enr['attack_scenario']}")
                b.append("")
            if enr.get("severity_rationale"):
                b.append(f"**Severity Rationale:** {enr['severity_rationale']}")
                b.append("")
            if enr.get("remediation"):
                b.append(f"**Remediation:** {enr['remediation']}")
                b.append("")
            refs = enr.get("references")
            if refs and isinstance(refs, list):
                b.append("**References:** " + "; ".join(str(rf) for rf in refs))
                b.append("")
        repro = self._extract_evidence_section_md(f, "replication")
        fix  = self._extract_evidence_section_md(f, "proposed_fix")
        rv   = (self._extract_evidence_section_md(f, "resolution_verdict")
                or self._extract_evidence_section_md(f, "review"))

        if repro:
            b.append(f"**Replication:** {repro}")
            b.append("")
        if fix:
            b.append(f"**Fix:** {fix}")
            b.append("")
        if rv:
            b.append(f"**Review:** {rv[:300]}")
            b.append("")
        if f.artifacts:
            b.append("**Artifacts:**")
            for a in f.artifacts:
                b.append(f"- `{a}`")
            b.append("")
        return b

    def _extract_evidence_section_md(self, f: Finding, key: str) -> str:
        for e in f.evidence:
            prefix = f"[{key}] "
            if e.startswith(prefix):
                return e[len(prefix):].strip()
        return ""
