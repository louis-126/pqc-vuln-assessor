"""Core data model for the PQC assessment pipeline.

Everything an agent produces is a `Finding`. The orchestrator routes on
`severity`, the report agent serialises, and the validation harness checks
whether the manually-found targets (WF-001, WF-004, CVE-2026-5460) were
rediscovered.
"""
from __future__ import annotations

import enum
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, ClassVar


class Severity(enum.IntEnum):
    """Ordered so escalation comparisons are just `>=`."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, s: str) -> "Severity":
        return cls[s.strip().upper()]

    def __str__(self) -> str:  # nicer report output
        return self.name


class Phase(enum.Enum):
    STATIC = "static"
    FUZZING = "fuzzing"
    DIFFERENTIAL = "differential"
    TIMING = "timing"
    REPRODUCTION = "reproduction"  # repro + impact triage (not weaponisation)
    REPORT = "report"


class Confidence(enum.Enum):
    """How sure we are this is a real bug vs. tool noise / expected behaviour."""
    CONFIRMED = "confirmed"      # reproduced, dual-tool agreement, or spec-anchored
    LIKELY = "likely"
    SUSPECTED = "suspected"
    EXPECTED_BEHAVIOUR = "expected_behaviour"  # e.g. FO implicit rejection


# CVSS 3.1 base-score helper. Deliberately minimal: we compute from a vector
# string so the LLM/agents only need to reason about metrics, not arithmetic.
_CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {  # depends on Scope; resolved in compute
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.5},
    },
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def default_cvss_vector(severity: "Severity", cwe: str | None = None) -> str:
    """Conservative fallback CVSS 3.1 vector when the reviewer doesn't supply one.

    Library-neutral: keyed on the assigned severity band and a coarse CWE class
    (timing/side-channel → confidentiality; memory/crash → availability;
    validation → integrity). The reviewer's own vector is always preferred; this
    only keeps the report from showing 0.0 on a confirmed finding.
    """
    import re as _re
    nums = set(_re.findall(r"\d+", cwe or ""))   # exact CWE numbers, not substrings
    # Coarse impact class from CWE.
    if nums & {"208", "385", "310", "330", "338", "203", "200"}:
        impact = "C:H/I:N/A:N"; ac = "H"          # side-channel / weak-RNG: info leak
    elif nums & {"787", "416", "415", "190"}:
        impact = "C:H/I:H/A:H"; ac = "L"          # memory-write / overflow: full
    elif nums & {"125", "476"}:
        impact = "C:H/I:N/A:H"; ac = "L"          # OOB read / null-deref
    elif nums & {"20", "680", "347", "345"}:
        impact = "C:N/I:H/A:N"; ac = "L"          # validation: integrity
    else:
        impact = "C:L/I:L/A:L"; ac = "L"
    # Severity band trims impacts down for the lower bands so the score tracks
    # the assigned severity rather than always maxing out.
    band = int(severity)
    if band <= 1:        # LOW / INFO
        impact = impact.replace("H", "L")
        av = "L"
    elif band == 2:      # MEDIUM
        impact = impact.replace("H", "L", 1)
        av = "N"
    else:                # HIGH / CRITICAL
        av = "N"
    return f"AV:{av}/AC:{ac}/PR:N/UI:N/S:U/{impact}"


def cvss31_base(vector: str) -> float:
    """Compute a CVSS 3.1 base score from a vector like
    'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'. Returns 0.0 on parse failure
    rather than raising — a missing score should not crash a report."""
    try:
        m = dict(part.split(":") for part in vector.replace("CVSS:3.1/", "").split("/"))
        scope = m["S"]
        iss = 1 - (
            (1 - _CVSS_WEIGHTS["C"][m["C"]])
            * (1 - _CVSS_WEIGHTS["I"][m["I"]])
            * (1 - _CVSS_WEIGHTS["A"][m["A"]])
        )
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        expl = (
            8.22
            * _CVSS_WEIGHTS["AV"][m["AV"]]
            * _CVSS_WEIGHTS["AC"][m["AC"]]
            * _CVSS_WEIGHTS["PR"][scope][m["PR"]]
            * _CVSS_WEIGHTS["UI"][m["UI"]]
        )
        if impact <= 0:
            return 0.0
        raw = (impact + expl) if scope == "U" else 1.08 * (impact + expl)
        # round-up to one decimal, capped at 10
        return min(10.0, (int(raw * 10) + (1 if raw * 10 % 1 else 0)) / 10)
    except Exception:
        return 0.0


@dataclass
class Finding:
    """A single observation. Agents append evidence as they corroborate."""
    title: str
    phase: Phase
    severity: Severity
    confidence: Confidence
    description: str
    file: str | None = None
    line: int | None = None
    entry_point: str | None = None
    cwe: str | None = None
    cvss_vector: str | None = None
    spec_reference: str | None = None        # e.g. "FIPS 203 §7.2"
    evidence: list[str] = field(default_factory=list)  # tool excerpts, repro notes
    artifacts: list[str] = field(default_factory=list)  # on-disk paths (harness, repro, etc.)
    matched_target: str | None = None        # WF-001 / WF-004 / CVE-2026-5460 if it maps
    discovered_by: str | None = None          # which model produced it (A/B compare)
    enrichment: dict | None = None           # v3: rich analytical narrative for the report
    id: str = field(default_factory=lambda: f"FND-{uuid.uuid4().hex[:8]}")
    created: float = field(default_factory=time.time)

    @property
    def cvss_score(self) -> float:
        return cvss31_base(self.cvss_vector) if self.cvss_vector else 0.0

    def add_evidence(self, source: str, text: str, cap: int = 4000) -> None:
        """Store evidence pre-truncated so it never bloats the report or a
        later LLM context window."""
        snippet = text if len(text) <= cap else text[:cap] + f"\n...[truncated {len(text)-cap} chars]"
        self.evidence.append(f"[{source}] {snippet}")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["phase"] = self.phase.value
        d["severity"] = self.severity.name
        d["confidence"] = self.confidence.value
        d["cvss_score"] = self.cvss_score
        return d


@dataclass
class AssessmentResult:
    """Aggregate of a full run. Owns the findings list and the validation check."""
    target: str
    library: str
    findings: list[Finding] = field(default_factory=list)
    started: float = field(default_factory=time.time)
    finished: float | None = None

    # Transparency data (populated by the researcher pipeline).
    #   coverage: what was actually examined — per-entry-point resolution and
    #             per-pass risky-line counts (deterministic; "Level A").
    #   triage:   model commentary on candidates it looked at and DISMISSED,
    #             with a reason (only when --explain; unverified; "Level B").
    coverage: dict[str, Any] = field(default_factory=dict)
    triage: list[dict[str, Any]] = field(default_factory=list)

    # v3: manual validation targets removed. Findings are reported purely on
    # their own merits. validation_status() now returns a neutral result so the
    # report agent and callers continue to work without a scoring harness.
    _VALIDATION_TARGETS_BY_LIB: ClassVar[dict[str, dict[str, str]]] = {}

    @property
    def VALIDATION_TARGETS(self) -> dict[str, str]:
        return {}

    def add(self, finding: Finding) -> Finding:
        self.findings.append(finding)
        return finding

    def by_min_severity(self, minimum: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity >= minimum]

    def validation_status(self) -> dict[str, Any]:
        """Which manual targets were rediscovered (regression check).
        Empty for libraries without known ground-truth targets."""
        targets = self.VALIDATION_TARGETS
        hit = {f.matched_target for f in self.findings if f.matched_target}
        per_target = {
            tid: {
                "description": desc,
                "rediscovered": tid in hit,
                "finding_ids": [f.id for f in self.findings if f.matched_target == tid],
            }
            for tid, desc in targets.items()
        }
        return {
            "targets": per_target,
            "rediscovered": len(hit & set(targets)),
            "total_targets": len(targets),
            "all_rediscovered": set(targets).issubset(hit) if targets else True,
            "has_targets": bool(targets),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "library": self.library,
            "started": self.started,
            "finished": self.finished,
            "duration_seconds": (round(self.finished - self.started, 1)
                                 if self.finished else None),
            "findings": [f.to_dict() for f in self.findings],
            "coverage": self.coverage,
            "triage": self.triage,
            "validation_status": self.validation_status(),
            "summary": {
                sev.name: len([f for f in self.findings if f.severity == sev])
                for sev in Severity
            },
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
