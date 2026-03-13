"""
workflow/graph.py
-----------------
WATCHDOG LangGraph state machine — Day 2 update.

Graph topology:

    scanner_node          ← A1: Bandit + AST scan, produces FindingRecord list
          │
          ▼
    analysis_node         ← A2 (Code Analyst) + A3 (Trust Analyst) run sequentially
          │                  produces CapabilityFingerprint + TrustSignal lists
          ▼
    patch_writer          ← placeholder (Day 3)
          │
          ▼
       reviewer  ──(corrections needed, retries left)──► patch_writer
          │
          │ (approved OR max retries)
          ▼
    report_generator      ← placeholder (Day 3/4)
          │
          ▼
         END

Changes from Day 1:
  - scanner_node now calls agents.scanner.run_scanner (real Bandit).
  - analysis_node is NEW — calls Code Analyst + Trust Analyst for each finding.
  - patch_writer / reviewer / report_generator remain stubs (Day 3).
"""

from __future__ import annotations

from typing import Literal

from langgraph.graph import END, StateGraph

# ── Real agent imports ─────────────────────────────────────────────────────────
from agents.scanner import run_scanner
from agents.code_analyst import run_code_analyst
from agents.trust_analyst import run_trust_analyst

# ── Placeholder imports (Day 3) ────────────────────────────────────────────────
from agents.critic import run_critic
from agents.reporter import run_reporter

from workflow.state import WatchdogState, make_initial_state

MAX_CORRECTION_CYCLES: int = 2


# ═══════════════════════════════════════════════════════════════════════════════
# Day 2 — Real agent nodes
# ═══════════════════════════════════════════════════════════════════════════════

def scanner_node(state: WatchdogState) -> dict:
    """
    Node 1 — Scanner Agent.
    Runs Bandit over target_path, filters test files, returns FindingRecord list.
    """
    return run_scanner(state)


def analysis_node(state: WatchdogState) -> dict:
    """
    Node 2 — Combined Code Analyst + Trust Analyst.

    Runs both agents sequentially against the findings in state and merges
    their outputs into a single partial state update.

    Why combined:
      Both agents read state["findings"] and are independent of each other,
      so running them together in one node avoids two full state round-trips
      while keeping the LangGraph topology simple for Day 2.
      Day 3 can split them into parallel Send() branches if needed.
    """
    # Code Analyst → fingerprints
    fp_update = run_code_analyst(state)

    # Trust Analyst → trust_signals
    ts_update = run_trust_analyst(state)

    return {**fp_update, **ts_update}


# ═══════════════════════════════════════════════════════════════════════════════
# Day 1 stubs (still placeholders — Day 3 will replace these)
# ═══════════════════════════════════════════════════════════════════════════════

def patch_writer_node(state: WatchdogState) -> dict:
    """
    Placeholder Patch Writer — Day 3 will generate PatchProposal objects here.
    For now, emits a synthetic placeholder patch per HIGH/CRITICAL finding
    so the reviewer node has something to evaluate.
    """
    from schemas.models import PatchProposal

    findings = state.get("findings", [])
    trust_signals = state.get("trust_signals", [])

    # Build a quick lookup: package → trust_score
    trust_lookup: dict[str, float] = {
        ts.package_name: ts.trust_score
        for ts in trust_signals
    }

    patches: list[PatchProposal] = []
    seen_packages: set[str] = set()

    for finding in findings:
        pkg = finding.package_name
        if pkg in seen_packages:
            continue
        seen_packages.add(pkg)

        trust = trust_lookup.get(pkg, 0.5)

        if trust < 0.30:
            action = "remove_dependency"
            rationale = (
                f"Package '{pkg}' has a critically low trust score ({trust:.2f}) "
                f"consistent with a supply chain compromise. Removal recommended."
            )
            confidence = 0.85
        elif finding.severity in ("HIGH", "CRITICAL"):
            action = "apply_code_patch"
            rationale = (
                f"Finding of type '{finding.finding_type}' detected in '{pkg}' "
                f"(severity={finding.severity}).  Manual code review and patching required."
            )
            confidence = 0.70
        else:
            action = "monitor_only"
            rationale = f"Low-severity finding in '{pkg}'; monitoring recommended."
            confidence = 0.60

        patches.append(PatchProposal(
            package_name=pkg,
            proposed_action=action,      # type: ignore[arg-type]
            rationale=rationale,
            confidence=confidence,
        ))

    print(f"[patch_writer] Generated {len(patches)} placeholder patch(es).")
    return {"patches": patches}


def reviewer_node(state: WatchdogState) -> dict:
    """
    Placeholder Reviewer / Critic — Day 3 will run adversarial LLM review here.
    For now, auto-approves all patches so the graph can reach END cleanly.
    """
    return run_critic(state)


def report_node(state: WatchdogState) -> dict:
    """
    Placeholder Report Generator — Day 4 will render Jinja2 templates here.
    """
    return run_reporter(state)


# ═══════════════════════════════════════════════════════════════════════════════
# Conditional routing
# ═══════════════════════════════════════════════════════════════════════════════

def _route_after_review(state: WatchdogState) -> Literal["patch_writer_node", "report_node"]:
    """
    Route back to patch_writer if the Critic rejected any patch and we have
    retries remaining; otherwise proceed to the report generator.
    """
    correction_count = state.get("correction_count", 0)
    verdicts = state.get("verdicts", [])
    has_rejection = any(not v.approved for v in verdicts)

    if has_rejection and correction_count < MAX_CORRECTION_CYCLES:
        print(
            f"[router] Rejection found — routing to patch_writer "
            f"(cycle {correction_count + 1}/{MAX_CORRECTION_CYCLES})"
        )
        return "patch_writer_node"

    if correction_count >= MAX_CORRECTION_CYCLES:
        print(f"[router] Max cycles ({MAX_CORRECTION_CYCLES}) reached — proceeding to report.")
    else:
        print("[router] All patches approved — proceeding to report.")

    return "report_node"


# ═══════════════════════════════════════════════════════════════════════════════
# Graph assembly
# ═══════════════════════════════════════════════════════════════════════════════

def build_graph() -> StateGraph:
    """
    Assemble and compile the WATCHDOG LangGraph state machine.

    Returns
    -------
    Compiled StateGraph ready to invoke.
    """
    graph = StateGraph(WatchdogState)

    # Register nodes
    graph.add_node("scanner_node",       scanner_node)
    graph.add_node("analysis_node",      analysis_node)
    graph.add_node("patch_writer_node",  patch_writer_node)
    graph.add_node("reviewer_node",      reviewer_node)
    graph.add_node("report_node",        report_node)

    # Entry point
    graph.set_entry_point("scanner_node")

    # Linear flow
    graph.add_edge("scanner_node",      "analysis_node")
    graph.add_edge("analysis_node",     "patch_writer_node")
    graph.add_edge("patch_writer_node", "reviewer_node")

    # Conditional: reviewer → (patch_writer | report)
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


# Module-level compiled graph (importable)
watchdog_graph = build_graph()


# ═══════════════════════════════════════════════════════════════════════════════
# __main__ smoke test
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "vuln_app/"
    print(f"Running WATCHDOG pipeline on: {target}")
    print("=" * 60)

    state = make_initial_state(target_path=target, use_llm=False)
    final = watchdog_graph.invoke(state)

    print("\n── Final State ──────────────────────────────────────────────")
    print(f"Findings       : {len(final.get('findings', []))}")
    print(f"Fingerprints   : {len(final.get('fingerprints', []))}")
    print(f"Trust signals  : {len(final.get('trust_signals', []))}")
    print(f"Patches        : {len(final.get('patches', []))}")
    print(f"Report length  : {len(final.get('final_report', ''))} chars")
    print("=" * 60)
