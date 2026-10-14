"""OrchestratorAgent — owns phase sequencing and escalation.

Escalation rules (from the handover):
  * static HIGH/CRITICAL  -> fuzzing + differential
  * fuzzing crash         -> reproduction (repro + impact triage)
  * timing HIGH/CRITICAL  -> reproduction

The orchestrator runs requested phases in dependency order, then runs any
phases that escalation pulled in, and finally always runs the report phase.
It is deliberately conservative: a phase whose tools are missing logs a notice
and is skipped rather than aborting the run.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path

from core import AssessmentResult, Phase, Severity, LLMClient

log = logging.getLogger("pqc")


class OrchestratorAgent:
    # Natural execution order; escalation can only add phases, never reorder.
    PHASE_ORDER = [
        Phase.STATIC, Phase.DIFFERENTIAL, Phase.FUZZING,
        Phase.TIMING, Phase.REPRODUCTION, Phase.REPORT,
    ]

    def __init__(self, llm: LLMClient, workdir: Path, agents: dict[Phase, object]):
        self.llm = llm
        self.workdir = Path(workdir)
        self.agents = agents  # Phase -> Agent instance

    def run(self, result: AssessmentResult, requested: set[Phase],
            context: dict) -> AssessmentResult:
        scheduled = set(requested)
        completed: set[Phase] = set()

        # Report always runs last; never schedule it for escalation logic.
        scheduled.discard(Phase.REPORT)

        for phase in self.PHASE_ORDER:
            if phase == Phase.REPORT:
                continue
            if phase not in scheduled or phase in completed:
                continue
            self._run_phase(phase, result, context)
            completed.add(phase)
            # Re-evaluate escalation after each phase so newly-added phases
            # later in PHASE_ORDER get picked up in this same pass.
            scheduled |= self._escalate(phase, result, scheduled, completed)

        # Always produce a report.
        if Phase.REPORT in self.agents:
            self._run_phase(Phase.REPORT, result, context)

        result.finished = time.time()
        return result

    def _run_phase(self, phase: Phase, result: AssessmentResult, context: dict) -> None:
        agent = self.agents.get(phase)
        if agent is None:
            log.info("no agent registered for phase %s; skipping", phase.value)
            return
        missing = getattr(agent, "missing_tools", lambda: [])()
        if missing:
            log.warning("[%s] missing tools %s — running in degraded mode",
                        phase.value, ", ".join(missing))
        log.info("=== phase: %s ===", phase.value)
        t0 = time.time()
        try:
            produced = agent.run(result, context)
            log.info("[%s] produced %d finding(s) in %.1fs",
                     phase.value, len(produced or []), time.time() - t0)
        except Exception as e:  # one phase failing must not sink the run
            log.exception("[%s] crashed: %s", phase.value, e)

    def _escalate(self, just_ran: Phase, result: AssessmentResult,
                  scheduled: set[Phase], completed: set[Phase]) -> set[Phase]:
        add: set[Phase] = set()
        new_findings = [f for f in result.findings if f.phase == just_ran]

        if just_ran == Phase.STATIC:
            if any(f.severity >= Severity.HIGH for f in new_findings):
                add |= {Phase.FUZZING, Phase.DIFFERENTIAL}
                log.info("escalation: static HIGH/CRITICAL -> fuzzing + differential")

        elif just_ran == Phase.FUZZING:
            # A crash finding from fuzzing triggers reproduction/triage.
            if any("crash" in (f.title.lower() + f.description.lower())
                   for f in new_findings):
                add.add(Phase.REPRODUCTION)
                log.info("escalation: fuzzing crash -> reproduction")

        elif just_ran == Phase.TIMING:
            if any(f.severity >= Severity.HIGH for f in new_findings):
                add.add(Phase.REPRODUCTION)
                log.info("escalation: timing HIGH/CRITICAL -> reproduction")

        # Only add phases not already done. (Adding an earlier-ordered phase
        # after it ran is a no-op because PHASE_ORDER iteration has passed it;
        # in practice all escalation targets come at or after their trigger.)
        return {p for p in add if p not in completed}
