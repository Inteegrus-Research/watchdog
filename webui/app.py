"""
webui/app.py
------------
WATCHDOG Gradio Web UI — Day 4 implementation target.

Day 1 status: minimal scaffold that launches a placeholder interface.
Full UI (scan form, live agent log, report viewer) built on Day 4.

Run with:
    python webui/app.py
"""

from __future__ import annotations

import os
import sys

# Ensure project root is on the path when running this file directly
_WEBUI_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_WEBUI_DIR, ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import gradio as gr


def _run_scan_placeholder(target_path: str) -> tuple[str, str]:
    """
    Placeholder scan function.

    Day 4 replacement will:
      1. Call workflow.graph.watchdog_graph.invoke(make_initial_state(target_path)).
      2. Stream agent log lines to the log box in real time.
      3. Return the final Markdown report and an HTML version for display.
    """
    if not target_path.strip():
        return "⚠️ Please enter a target path.", ""

    log = (
        f"[scanner_agent]      Scanning: {target_path}\n"
        "[exploit_reasoner]   Analysing findings...\n"
        "[patch_writer]       Generating patches...\n"
        "[reviewer]           Reviewing patches...\n"
        "[report_generator]   Building report...\n\n"
        "✅ Scan complete (placeholder — full pipeline active Day 4)."
    )

    report = (
        f"# WATCHDOG Security Advisory\n\n"
        f"**Target:** `{target_path}`\n\n"
        "_Full report generated on Day 4 when all agents are wired in._\n\n"
        "## Quick Demo Findings\n\n"
        "| # | Type | Severity | File |\n"
        "|---|------|----------|------|\n"
        "| 1 | SQL Injection | HIGH | `vuln_app/app.py:60` |\n"
        "| 2 | IDOR | MEDIUM | `vuln_app/app.py:100` |\n"
        "| 3 | Hardcoded Secret | HIGH | `vuln_app/app.py:30` |\n"
    )

    return log, report


def build_ui() -> gr.Blocks:
    """Build and return the Gradio Blocks application."""
    with gr.Blocks(
        title="WATCHDOG — Supply Chain Threat Intelligence",
        theme=gr.themes.Base(primary_hue="blue"),
    ) as demo:

        gr.Markdown(
            """
            # 🐕 WATCHDOG
            ### Autonomous Software Supply Chain Threat Intelligence Agent
            *Detects zero-day supply chain attacks before any CVE exists.*
            """
        )

        with gr.Row():
            with gr.Column(scale=3):
                target_input = gr.Textbox(
                    label="Target Path",
                    placeholder="e.g.  vuln_app/  or  /path/to/your/project",
                    value="vuln_app/",
                )
                scan_btn = gr.Button("🔍 Run WATCHDOG Scan", variant="primary")
            with gr.Column(scale=1):
                gr.Markdown(
                    """
                    **Quick targets**
                    - `vuln_app/` — demo Flask app
                    - `.` — scan entire project
                    """
                )

        with gr.Row():
            log_box = gr.Textbox(
                label="Agent Log",
                lines=12,
                interactive=False,
                placeholder="Agent output will appear here...",
            )

        report_box = gr.Markdown(label="Security Advisory")

        scan_btn.click(
            fn=_run_scan_placeholder,
            inputs=[target_input],
            outputs=[log_box, report_box],
        )

        gr.Markdown(
            """
            ---
            *WATCHDOG v0.1 · Day 1 scaffold · Full pipeline active Day 4*
            """
        )

    return demo


def main() -> None:
    """Entry point — launch the Gradio app."""
    demo = build_ui()
    demo.launch(
        server_name="0.0.0.0",
        server_port=7860,
        share=False,
        show_error=True,
    )


if __name__ == "__main__":
    main()
