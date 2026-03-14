"""
workflow/graph.py
-----------------
WATCHDOG LangGraph state machine — Day 3 update.

Full pipeline topology:

    scanner_node
          │  findings: List[FindingRecord]
          ▼
    analysis_node   ← Code Analyst (fingerprints) + Trust Analyst (trust_signals)
          │
          ▼
    threat_correlator_node   ← semantic ChromaDB search → threat_assessments
          │
          ▼
    patch_writer_node   ← rule-based patch generation, IDOR flaw on pass 1
          │
          ▼
    reviewer_node   ← deterministic checks + optional LLM review → verdicts
          │
    ╔═════╩══════════════════════════════════════════╗
    ║  conditional _route_after_review()             ║
    ║  reject + retries left → patch_writer_node     ║
    ║  approve OR max retries → report_node          ║
    ╚═════════════════════════════════════════════════╝
          │
          ▼
    report_node   → END
"""

from __future__ import annotations

from typing import Literal

from langgraph.graph import END, StateGraph

# ── Real agent imports ─────────────────────────────────────────────────────────
from agents.scanner           import run_scanner
from agents.code_analyst      import run_code_analyst
from agents.trust_analyst     import run_trust_analyst
from agents.threat_correlator import run_threat_correlator
from agents.patch_writer      import run_patch_writer
from agents.reviewer          import run_reviewer
from agents.reporter          import run_reporter

from workflow.state import WatchdogState, make_initial_state

MAX_CORRECTION_CYCLES: int = 2


# ═══════════════════════════════════════════════════════════════════════════════
# Node definitions
# ═══════════════════════════════════════════════════════════════════════════════

def scanner_node(state: WatchdogState) -> dict:
    """A1 — Scanner: Bandit + AST scan → FindingRecord list."""
    return run_scanner(state)


def analysis_node(state: WatchdogState) -> dict:
    """A2+A3 — Code Analyst + Trust Analyst running sequentially."""
    fp_update = run_code_analyst(state)
    ts_update = run_trust_analyst(state)
    return {**fp_update, **ts_update}


def threat_correlator_node(state: WatchdogState) -> dict:
    """A4 — Threat Correlator: ChromaDB similarity search → ThreatAssessment list."""
    return run_threat_correlator(state)


def patch_writer_node(state: WatchdogState) -> dict:
    """A5 — Patch Writer: rule-based patch generation with deliberate IDOR flaw on pass 1."""
    return run_patch_writer(state)


def reviewer_node(state: WatchdogState) -> dict:
    """A6 — Reviewer: deterministic + LLM adversarial review → verdicts + mandates."""
    return run_reviewer(state)


def report_node(state: WatchdogState) -> dict:
    """A7 — Report Generator (full implementation Day 4; stub today)."""
    return run_reporter(state)


# ═══════════════════════════════════════════════════════════════════════════════
# Conditional routing
# ═══════════════════════════════════════════════════════════════════════════════

def _route_after_review(
    state: WatchdogState,
) -> Literal["patch_writer_node", "report_node"]:
    """
    Route back to patch_writer if any patch was rejected AND we have retries left.
    Otherwise proceed to the report generator.
    """
    correction_count = state.get("correction_count", 0)
    verdicts = state.get("verdicts", [])
    has_rejection = any(not v.approved for v in verdicts)

    if has_rejection and correction_count < MAX_CORRECTION_CYCLES:
        print(
            f"[router] ↩  Rejection detected — routing to patch_writer "
            f"(cycle {correction_count}/{MAX_CORRECTION_CYCLES})"
        )
        return "patch_writer_node"

    if correction_count >= MAX_CORRECTION_CYCLES:
        print(f"[router] ⚠  Max correction cycles ({MAX_CORRECTION_CYCLES}) reached — "
              "accepting current patches and generating report.")
    else:
        n_approved = sum(1 for v in verdicts if v.approved)
        print(f"[router] ✅  All {n_approved} patch(es) approved — generating report.")

    return "report_node"


# ═══════════════════════════════════════════════════════════════════════════════
# Graph assembly
# ═══════════════════════════════════════════════════════════════════════════════

def build_graph() -> StateGraph:
    """
    Assemble and compile the WATCHDOG LangGraph.

    Returns
    -------
    Compiled StateGraph ready to .invoke().
    """
    graph = StateGraph(WatchdogState)

    # ── Nodes ──────────────────────────────────────────────────────────────────
    graph.add_node("scanner_node",           scanner_node)
    graph.add_node("analysis_node",          analysis_node)
    graph.add_node("threat_correlator_node", threat_correlator_node)
    graph.add_node("patch_writer_node",      patch_writer_node)
    graph.add_node("reviewer_node",          reviewer_node)
    graph.add_node("report_node",            report_node)

    # ── Entry ──────────────────────────────────────────────────────────────────
    graph.set_entry_point("scanner_node")

    # ── Linear edges ───────────────────────────────────────────────────────────
    graph.add_edge("scanner_node",           "analysis_node")
    graph.add_edge("analysis_node",          "threat_correlator_node")
    graph.add_edge("threat_correlator_node", "patch_writer_node")
    graph.add_edge("patch_writer_node",      "reviewer_node")

    # ── Conditional: reviewer → patch_writer (retry) OR report ────────────────
    graph.add_conditional_edges(
        "reviewer_node",
        _route_after_review,
        {
            "patch_writer_node": "patch_writer_node",
            "report_node":       "report_node",
        },
    )

    graph.add_edge("report_node", END)

    return graph.compile()


# Module-level compiled graph (importable by webui and scripts)
watchdog_graph = build_graph()


# ═══════════════════════════════════════════════════════════════════════════════
# __main__ quick smoke test
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    target  = sys.argv[1] if len(sys.argv) > 1 else "vuln_app/"
    use_llm = "--llm" in sys.argv

    print(f"WATCHDOG — full pipeline smoke test")
    print(f"  target  : {target}")
    print(f"  use_llm : {use_llm}")
    print("=" * 64)

    state  = make_initial_state(target_path=target, use_llm=use_llm)
    final  = watchdog_graph.invoke(state)

    print("\n── Final State ──────────────────────────────────────────────")
    print(f"  Findings           : {len(final.get('findings',      []))}")
    print(f"  Fingerprints       : {len(final.get('fingerprints',  []))}")
    print(f"  Trust signals      : {len(final.get('trust_signals', []))}")
    print(f"  Threat assessments : {len(final.get('threat_assessments', []))}")
    print(f"  Patches            : {len(final.get('patches',       []))}")
    print(f"  Verdicts           : {len(final.get('verdicts',      []))}")
    print(f"  Correction count   : {final.get('correction_count', 0)}")
    print(f"  Final report       : {len(final.get('final_report', ''))} chars")
    print("=" * 64)
