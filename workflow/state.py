"""
workflow/state.py
-----------------
Shared LangGraph state for the WATCHDOG pipeline.

Day 2 additions:
  - fingerprints  : List[CapabilityFingerprint]  (from Code Analyst Agent)
  - trust_signals : List[TrustSignal]            (from Trust Analyst Agent)
  - use_llm       : bool                         (runtime flag to enable/disable Ollama)
"""

from __future__ import annotations

from typing import List, TypedDict

from schemas.models import (
    CapabilityFingerprint,
    CorrectionMandate,
    ExploitAssessment,
    FindingRecord,
    PatchProposal,
    ReviewVerdict,
    ThreatAssessment,
    TrustSignal,
)


class WatchdogState(TypedDict):
    """
    Shared state dictionary flowing through every node in the WATCHDOG LangGraph.

    Fields added in Day 1
    ----------------------
    target_path        : str
    findings           : List[FindingRecord]
    assessments        : List[ExploitAssessment]
    threat_assessments : List[ThreatAssessment]
    patches            : List[PatchProposal]
    verdicts           : List[ReviewVerdict]
    correction_mandates: List[CorrectionMandate]
    correction_count   : int
    final_report       : str

    Fields added in Day 2
    ----------------------
    fingerprints  : List[CapabilityFingerprint]
        Code capability fingerprints built by the Code Analyst Agent.
        One entry per unique (package, file) pair.

    trust_signals : List[TrustSignal]
        Maintainer provenance signals produced by the Trust Analyst Agent.
        One entry per unique package_name in findings.

    use_llm : bool
        Runtime flag.  Set False to skip Ollama calls (useful in CI / demo
        environments where Ollama is not running).  Defaults to True.
    """

    # ── Day 1 ──────────────────────────────────────────────────────────────────
    target_path: str
    findings: List[FindingRecord]
    assessments: List[ExploitAssessment]
    threat_assessments: List[ThreatAssessment]
    patches: List[PatchProposal]
    verdicts: List[ReviewVerdict]
    correction_mandates: List[CorrectionMandate]
    correction_count: int
    final_report: str

    # ── Day 2 ──────────────────────────────────────────────────────────────────
    fingerprints: List[CapabilityFingerprint]
    trust_signals: List[TrustSignal]
    use_llm: bool


def make_initial_state(
    target_path: str,
    use_llm: bool = True,
) -> WatchdogState:
    """
    Return a zeroed-out WatchdogState ready for a fresh pipeline run.

    Parameters
    ----------
    target_path : str
        Directory or file to scan.
    use_llm : bool
        Pass False to disable Ollama LLM calls (rule-based fallback is used).
    """
    return WatchdogState(
        # ── Day 1 fields ───────────────────────────────────────────────────────
        target_path=target_path,
        findings=[],
        assessments=[],
        threat_assessments=[],
        patches=[],
        verdicts=[],
        correction_mandates=[],
        correction_count=0,
        final_report="",
        # ── Day 2 fields ───────────────────────────────────────────────────────
        fingerprints=[],
        trust_signals=[],
        use_llm=use_llm,
    )
