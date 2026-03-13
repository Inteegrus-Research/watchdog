"""
agents/code_analyst.py
-----------------------
Code Analyst Agent — Day 2 implementation target.

Responsibilities:
  1. Receive FindingRecord objects from the Scanner Agent.
  2. For each HIGH/CRITICAL finding, call the local Ollama LLM with a
     structured prompt asking it to reason about whether the finding
     constitutes a real exploit path (chain-of-thought reasoning).
  3. Build a CapabilityFingerprint for each suspicious package — a compact
     boolean/text summary used by the Threat Correlator for ChromaDB search.
  4. Return ExploitAssessment objects in state.

Inputs  (from WatchdogState):
  - findings: List[FindingRecord]

Outputs (written to WatchdogState):
  - assessments: List[ExploitAssessment]
"""

from __future__ import annotations

# Day 2 imports (uncomment when implementing):
# import ollama
# from schemas.models import CapabilityFingerprint, ExploitAssessment, FindingRecord
# from workflow.state import WatchdogState


def run_code_analyst(state: dict) -> dict:
    """
    LangGraph node function for the Code Analyst Agent.

    Placeholder — returns state unchanged.
    Full implementation on Day 2.
    """
    findings = state.get("findings", [])
    print(f"[code_analyst] Analysing {len(findings)} findings with LLM reasoning...")
    # TODO Day 2: call Ollama, produce ExploitAssessment + CapabilityFingerprint
    return {}
