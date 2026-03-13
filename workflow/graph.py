"""
workflow/graph.py
-----------------
LangGraph state machine skeleton for the WATCHDOG pipeline.

Graph topology (Day 1 — placeholder nodes):

    scanner_agent
         │
         ▼
    exploit_reasoner
         │
         ▼
    patch_writer ◄──────────────────────────────┐
         │                                      │
         ▼                                      │
      reviewer ──(corrections needed, retries left)──┘
         │
         │ (approved OR max retries exhausted)
         ▼
    report_generator
         │
         ▼
       END

Each node currently prints its name and returns the state unchanged.
Real agent implementations will be wired in on Days 2–4.
"""

from __future__ import annotations

from typing import Literal

from langgraph.graph import END, StateGraph

from workflow.state import WatchdogState, make_initial_state

# ── Maximum number of patch correction cycles before we give up and report ────
MAX_CORRECTION_CYCLES: int = 2


# ═══════════════════════════════════════════════════════════════════════════════
# Placeholder Agent Nodes
# Each function signature must match: (state: WatchdogState) -> dict
# (returning a dict of partial state updates is the LangGraph convention)
# ═══════════════════════════════════════════════════════════════════════════════


def scanner_agent(state: WatchdogState) -> dict:
    """
    SCANNER AGENT (placeholder)
    ---------------------------
    Real implementation (Day 2) will:
      - Walk the target_path directory tree.
      - Skip test files (test_*.py) and virtual-env directories.
      - Run Bandit for static analysis and parse its JSON output.
      - Perform custom AST analysis (utils/ast_extractor.py) to detect
        new imports, network calls, subprocess invocations, etc.
      - Return a list of FindingRecord objects.
    """
    print("[scanner_agent] Scanning target for vulnerabilities...")
    # Placeholder: returns state unchanged
    return {}


def exploit_reasoner(state: WatchdogState) -> dict:
    """
    EXPLOIT REASONER / CODE ANALYST AGENT (placeholder)
    -----------------------------------------------------
    Real implementation (Day 2) will:
      - Receive findings from the Scanner Agent.
      - For each high-severity finding, query the LLM (via Ollama) to reason
        about whether the finding constitutes a credible exploit path.
      - Produce ExploitAssessment objects summarising new capabilities and
        the likelihood of exploitation.
      - Also build a CapabilityFingerprint for Threat Correlator input.
    """
    print("[exploit_reasoner] Reasoning about exploit potential...")
    return {}


def patch_writer(state: WatchdogState) -> dict:
    """
    PATCH WRITER AGENT (placeholder)
    ---------------------------------
    Real implementation (Day 3) will:
      - Receive ExploitAssessments and ThreatAssessments.
      - For each CRITICAL/HIGH threat, generate a PatchProposal:
          * pin_version: suggest the last safe version.
          * apply_code_patch: generate a unified diff.
          * remove_dependency: recommend removal.
      - If correction_mandates exist (from a previous Critic rejection),
        incorporate the specific correction instructions before re-generating.
    """
    print("[patch_writer] Generating patch proposals...")
    return {}


def reviewer(state: WatchdogState) -> dict:
    """
    CRITIC / REVIEWER AGENT (placeholder)
    ---------------------------------------
    Real implementation (Day 3) will:
      - Evaluate each PatchProposal for correctness, safety, and completeness.
      - Approve safe, well-reasoned patches (ReviewVerdict.approved = True).
      - Reject flawed patches with specific feedback (ReviewVerdict.approved = False).
      - Emit CorrectionMandate objects for rejected patches.
      - Increment correction_count in state.
    """
    print("[reviewer] Reviewing patch proposals...")
    # Placeholder: auto-approve everything so the graph reaches END
    return {"correction_count": state.get("correction_count", 0)}


def report_generator(state: WatchdogState) -> dict:
    """
    REPORT GENERATOR AGENT (placeholder)
    --------------------------------------
    Real implementation (Day 4) will:
      - Aggregate all findings, assessments, threat verdicts, and patches.
      - Render the Jinja2 templates (templates/report.md.j2 and report.html.j2).
      - Produce a complete security advisory with:
          * Executive summary
          * Per-package findings with code citations
          * Historical attack pattern references
          * Concrete remediation steps
      - Store the rendered report in state["final_report"].
    """
    print("[report_generator] Generating final security report...")
    report_text = (
        "# WATCHDOG Security Report\n\n"
        "_Placeholder report — real content generated on Day 4._\n\n"
        f"Target: `{state.get('target_path', 'unknown')}`\n"
        f"Findings: {len(state.get('findings', []))}\n"
        f"Patches: {len(state.get('patches', []))}\n"
    )
    return {"final_report": report_text}


# ═══════════════════════════════════════════════════════════════════════════════
# Conditional Routing
# ═══════════════════════════════════════════════════════════════════════════════


def _route_after_review(state: WatchdogState) -> Literal["patch_writer", "report_generator"]:
    """
    Conditional edge function called after the reviewer node.

    Logic:
    - If any patches were rejected AND we have retries remaining → route back
      to patch_writer for a correction cycle.
    - Otherwise (all approved, or max retries exhausted) → proceed to report.
    """
    correction_count = state.get("correction_count", 0)
    verdicts = state.get("verdicts", [])

    # Check whether any verdict was a rejection
    has_rejection = any(not v.approved for v in verdicts)

    if has_rejection and correction_count < MAX_CORRECTION_CYCLES:
        print(
            f"[router] Rejection found — routing to patch_writer "
            f"(cycle {correction_count + 1}/{MAX_CORRECTION_CYCLES})"
        )
        return "patch_writer"

    if correction_count >= MAX_CORRECTION_CYCLES:
        print(
            f"[router] Max correction cycles ({MAX_CORRECTION_CYCLES}) reached — "
            "proceeding to report with best-effort patches."
        )
    else:
        print("[router] All patches approved — proceeding to report.")

    return "report_generator"


# ═══════════════════════════════════════════════════════════════════════════════
# Graph Assembly
# ═══════════════════════════════════════════════════════════════════════════════


def build_graph() -> StateGraph:
    """
    Assemble and compile the WATCHDOG LangGraph state machine.

    Returns
    -------
    StateGraph
        A compiled graph ready to invoke with a WatchdogState dict.
    """
    graph = StateGraph(WatchdogState)

    # ── Register nodes ─────────────────────────────────────────────────────────
    graph.add_node("scanner_agent", scanner_agent)
    graph.add_node("exploit_reasoner", exploit_reasoner)
    graph.add_node("patch_writer", patch_writer)
    graph.add_node("reviewer", reviewer)
    graph.add_node("report_generator", report_generator)

    # ── Entry point ────────────────────────────────────────────────────────────
    graph.set_entry_point("scanner_agent")

    # ── Linear edges ──────────────────────────────────────────────────────────
    graph.add_edge("scanner_agent", "exploit_reasoner")
    graph.add_edge("exploit_reasoner", "patch_writer")
    graph.add_edge("patch_writer", "reviewer")

    # ── Conditional edge: reviewer → (patch_writer | report_generator) ────────
    graph.add_conditional_edges(
        "reviewer",
        _route_after_review,
        {
            "patch_writer": "patch_writer",
            "report_generator": "report_generator",
        },
    )

    # ── Terminal edge ──────────────────────────────────────────────────────────
    graph.add_edge("report_generator", END)

    return graph.compile()


# ── Module-level compiled graph (importable by other modules) ──────────────────
watchdog_graph = build_graph()


# ═══════════════════════════════════════════════════════════════════════════════
# Main — smoke test
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("WATCHDOG — LangGraph Skeleton Smoke Test")
    print("=" * 60)

    initial_state = make_initial_state(target_path="vuln_app/")

    print(f"Starting graph with target: {initial_state['target_path']}\n")

    final_state = watchdog_graph.invoke(initial_state)

    print("\n--- Final State Summary ---")
    print(f"Findings         : {len(final_state.get('findings', []))}")
    print(f"Assessments      : {len(final_state.get('assessments', []))}")
    print(f"Patches          : {len(final_state.get('patches', []))}")
    print(f"Correction cycles: {final_state.get('correction_count', 0)}")
    print(f"Report length    : {len(final_state.get('final_report', ''))} chars")
    print("\nFinal Report Preview:")
    print(final_state.get("final_report", "(empty)"))
    print("=" * 60)
    print("Graph ran successfully ✓")
