"""
agents/reporter.py
-------------------
Report Generator Agent — Day 4 implementation target.

Responsibilities:
  1. Aggregate all state fields into a single ReportContext object.
  2. Render the Jinja2 Markdown template (templates/report.md.j2) to produce
     a human-readable security advisory.
  3. Render the Jinja2 HTML template (templates/report.html.j2) for the
     Gradio Web UI and any PDF export.
  4. Write the rendered reports to disk under reports/<timestamp>/.
  5. Return the Markdown string in state["final_report"].

Output format for each flagged package:
  - Executive summary (risk level, one-line verdict)
  - Code-level findings with file path, line number, and snippet
  - Closest historical attack pattern + similarity score
  - Maintainer trust summary + anomalies
  - Concrete remediation steps (pin version / remove / patch)

Inputs  (from WatchdogState):
  - findings, assessments, threat_assessments, patches, verdicts

Outputs (written to WatchdogState):
  - final_report: str  (Markdown)
"""

from __future__ import annotations

# Day 4 imports (uncomment when implementing):
# from datetime import datetime, timezone
# from pathlib import Path
# from jinja2 import Environment, FileSystemLoader
# from rich.console import Console
# from workflow.state import WatchdogState


def run_reporter(state: dict) -> dict:
    """
    LangGraph node function for the Report Generator Agent.

    Placeholder — returns a minimal stub report.
    Full implementation on Day 4.
    """
    findings = state.get("findings", [])
    patches = state.get("patches", [])
    target = state.get("target_path", "unknown")

    print(f"[reporter] Generating security advisory for '{target}'...")

    stub_report = (
        "# WATCHDOG Security Advisory\n\n"
        "> _Full report template rendered on Day 4._\n\n"
        f"**Target:** `{target}`  \n"
        f"**Findings:** {len(findings)}  \n"
        f"**Patches proposed:** {len(patches)}  \n"
    )

    # TODO Day 4: render Jinja2 templates, write to disk, return full report
    return {"final_report": stub_report}
