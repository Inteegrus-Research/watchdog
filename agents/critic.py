"""
agents/critic.py
-----------------
Critic Agent — Day 3 implementation target.

Responsibilities:
  1. Evaluate each PatchProposal produced by the Patch Writer Agent using
     a separate LLM call with an adversarial "red-team reviewer" system prompt.
  2. Check for:
       - Correctness: does the proposed safe version actually exist on PyPI?
       - Completeness: are all HIGH/CRITICAL findings addressed?
       - Safety: does the code patch introduce new issues?
       - Clarity: is the rationale clear enough for a developer to act on?
  3. Approve clean proposals (ReviewVerdict.approved = True).
  4. Reject flawed proposals with specific, actionable feedback and emit a
     CorrectionMandate so the Patch Writer knows exactly what to fix.
  5. Increment correction_count in state.
  6. The graph's conditional edge reads correction_count to enforce the
     MAX_CORRECTION_CYCLES = 2 limit.

Inputs  (from WatchdogState):
  - patches: List[PatchProposal]
  - threat_assessments: List[ThreatAssessment]

Outputs (written to WatchdogState):
  - verdicts: List[ReviewVerdict]
  - correction_mandates: List[CorrectionMandate]
  - correction_count: int  (incremented)
"""

from __future__ import annotations

# Day 3 imports (uncomment when implementing):
# import ollama
# from schemas.models import CorrectionMandate, ReviewVerdict
# from workflow.state import WatchdogState


def run_critic(state: dict) -> dict:
    """
    LangGraph node function for the Critic Agent.

    Placeholder — auto-approves all patches and returns state unchanged.
    Full implementation on Day 3.
    """
    patches = state.get("patches", [])
    print(f"[critic] Reviewing {len(patches)} patch proposals...")
    # TODO Day 3: adversarial LLM review, emit ReviewVerdict + CorrectionMandate objects
    return {"correction_count": state.get("correction_count", 0)}
