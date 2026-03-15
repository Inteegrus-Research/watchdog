"""
webui/app.py
------------
WATCHDOG Gradio Web UI — Day 4 full implementation.

Features:
  - Target path input + LLM toggle
  - Real-time agent log (captured stdout → live updates via generator)
  - Tabbed result view: HTML report + Markdown + pipeline stats
  - Download button for the HTML report
  - Graceful error handling

Run with:
    python webui/app.py
    # or
    python -m webui.app
"""

from __future__ import annotations

import io
import os
import sys
import tempfile
import time
import traceback
from contextlib import redirect_stdout
from datetime import datetime

import logging
from transformers import logging as transformers_logging

transformers_logging.set_verbosity_error()


_WEBUI_DIR    = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_WEBUI_DIR, ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import gradio as gr

# ── Pipeline runner ────────────────────────────────────────────────────────────

def run_pipeline(target_path: str, use_llm: bool) -> dict:
    """
    Execute the full WATCHDOG LangGraph pipeline and return the final state.

    All agent print() output is captured and returned in state["_agent_log"].
    """
    from workflow.graph import build_graph
    from workflow.state import make_initial_state

    abs_target = os.path.abspath(target_path.strip())

    # Capture all agent stdout
    log_buf = io.StringIO()
    t0 = time.perf_counter()

    with redirect_stdout(log_buf):
        graph = build_graph()
        state = make_initial_state(abs_target, use_llm=use_llm)
        final = graph.invoke(state)

    elapsed = time.perf_counter() - t0
    final["_agent_log"]           = log_buf.getvalue()
    final["_pipeline_duration_s"] = elapsed
    return final


# ── Gradio callback ────────────────────────────────────────────────────────────

def scan_and_report(
    target_path: str,
    use_llm: bool,
    progress=gr.Progress(track_tqdm=False),
):
    """
    Gradio handler — runs the pipeline and yields progressive UI updates.

    Yields tuples matching outputs = [status_md, log_box, report_html, stats_md, dl_file]
    """
    # ── Input validation ──────────────────────────────────────────────────────
    target_path = target_path.strip() or "vuln_app/"
    abs_target  = os.path.abspath(target_path)

    if not os.path.exists(abs_target):
        error_md = (
            f"## ❌ Target not found\n\n"
            f"Path `{abs_target}` does not exist.  "
            f"Please enter a valid directory or file."
        )
        yield error_md, "", "<p style='color:#ff4444'>Target path not found.</p>", "", None
        return

    # ── Phase indicator updates ────────────────────────────────────────────────
    phases = [
        ("🔍 Scanning codebase with Bandit...",        5),
        ("🔬 Running Code Analyst + Trust Analyst...", 20),
        ("🎯 Correlating against attack patterns...",  40),
        ("🩹 Generating patch proposals...",           55),
        ("⚖️  Reviewing patches (adversarial check)...",70),
        ("📊 Generating security report...",           90),
    ]

    for msg, pct in phases:
        progress(pct / 100, desc=msg)
        status_md = f"## {msg}\n\n_Running WATCHDOG pipeline on `{target_path}`..._"
        yield status_md, f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", "", "", None
        time.sleep(0.05)  # small yield to let Gradio render the status

    # ── Run pipeline ──────────────────────────────────────────────────────────
    progress(0.95, desc="Finalising report...")
    try:
        final = run_pipeline(target_path, use_llm)
    except Exception as exc:
        tb   = traceback.format_exc()
        err  = f"## ❌ Pipeline Error\n\n```\n{exc}\n```\n\n<details><summary>Traceback</summary>\n\n```\n{tb}\n```\n\n</details>"
        yield err, tb, f"<p style='color:#ff4444'>Pipeline failed: {exc}</p>", "", None
        return

    progress(1.0, desc="Done!")

    # ── Extract results ───────────────────────────────────────────────────────
    agent_log       = final.get("_agent_log",           "")
    elapsed         = final.get("_pipeline_duration_s",  0.0)
    findings        = final.get("findings",              [])
    threats         = final.get("threat_assessments",    [])
    patches         = final.get("patches",               [])
    verdicts        = final.get("verdicts",              [])
    corr_count      = final.get("correction_count",       0)
    markdown_report = final.get("final_report",          "")
    html_report     = final.get("final_report_html",     "")

    # ── Re-render HTML if reporter wasn't wired yet (safety fallback) ─────────
    if not html_report and markdown_report:
        from agents.reporter import generate_report
        _, html_report = generate_report(final, elapsed)
    elif not html_report:
        from agents.reporter import generate_report
        markdown_report, html_report = generate_report(final, elapsed)

    # ── Pipeline stats Markdown ───────────────────────────────────────────────
    crit_n  = sum(1 for t in threats if t.risk_level == "CRITICAL")
    high_n  = sum(1 for t in threats if t.risk_level == "HIGH")
    appr_n  = sum(1 for v in verdicts if v.approved)
    rej_n   = sum(1 for v in verdicts if not v.approved)

    stats_md = f"""### 📊 Pipeline Results

| Metric | Value |
|--------|-------|
| **Target** | `{target_path}` |
| **Duration** | {elapsed:.1f}s |
| **Findings** | {len(findings)} |
| **Critical packages** | {crit_n} |
| **High risk packages** | {high_n} |
| **Patches generated** | {len(patches)} |
| **Patches approved** | {appr_n} |
| **Patches rejected** | {rej_n} |
| **Correction cycles** | {corr_count} |
| **LLM enrichment** | {'✅ Ollama' if use_llm else '⚡ Rule-based'} |

{'> 🔄 **Self-correction loop triggered** — ' + str(corr_count) + ' correction cycle(s) completed.' if corr_count > 0 else ''}
"""

    # ── Save HTML to temp file for download ───────────────────────────────────
    tmp_path: str | None = None
    try:
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix="_watchdog_report.html",
            delete=False, encoding="utf-8",
        )
        tmp.write(html_report)
        tmp.close()
        tmp_path = tmp.name
    except Exception:
        pass

    # ── Final status ──────────────────────────────────────────────────────────
    final_status = (
        f"## ✅ Scan Complete\n\n"
        f"WATCHDOG found **{len(findings)} finding(s)** in `{target_path}` "
        f"({elapsed:.1f}s).  "
        f"{'⛔ **CRITICAL** risk detected.' if crit_n else '🟠 High risk detected.' if high_n else '✅ No critical threats.'}"
    )

    yield final_status, agent_log, html_report, stats_md, tmp_path


# ── UI ─────────────────────────────────────────────────────────────────────────

_INTRO_MD = """
# 🐕 WATCHDOG
### Autonomous Software Supply Chain Threat Intelligence Agent

Detects **zero-day supply chain attacks** before any CVE exists — using multi-agent LLM reasoning,
behavioral fingerprinting, and semantic similarity search against historical attack patterns.

**Pipeline:** Scanner → Code Analyst → Trust Analyst → Threat Correlator → Patch Writer → Reviewer (self-correction loop) → Report
"""

_INSTRUCTIONS_MD = """
### Quick Start

1. Enter the path to a Python project (e.g. `vuln_app/`)
2. Toggle **LLM enrichment** (requires Ollama + mistral running locally)
3. Click **Run WATCHDOG Scan**
4. View the interactive HTML report in the **Report** tab
5. Download the report for sharing

**Demo targets:**
- `vuln_app/` — includes SQLi, IDOR, hardcoded secret, and the `computil` backdoor
- `.` — scan the entire WATCHDOG codebase
"""


def build_ui() -> gr.Blocks:
    """Construct and return the Gradio Blocks application."""
    with gr.Blocks(
        title="🐕 WATCHDOG — Supply Chain Threat Intelligence",
        theme=gr.themes.Base(
            primary_hue="blue",
            secondary_hue="slate",
            neutral_hue="slate",
            font=[gr.themes.GoogleFont("Inter"), "ui-sans-serif", "system-ui"],
        ),
        css="""
        .gradio-container { max-width: 1200px !important; }
        .status-box { font-family: monospace !important; }
        #report-frame { border: none !important; }
        """,
    ) as demo:

        gr.Markdown(_INTRO_MD)

        with gr.Tabs():

            # ── Tab 1: Scan ──────────────────────────────────────────────────
            with gr.TabItem("🔍 Scan", id="scan"):
                with gr.Row():
                    with gr.Column(scale=3):
                        target_input = gr.Textbox(
                            label="Target Path",
                            placeholder="vuln_app/",
                            value="vuln_app/",
                            info="Path to the Python project or file to scan.",
                        )
                        with gr.Row():
                            use_llm_check = gr.Checkbox(
                                label="Enable LLM enrichment (Ollama + mistral required)",
                                value=False,
                            )
                            scan_btn = gr.Button(
                                "🔍 Run WATCHDOG Scan",
                                variant="primary",
                                scale=2,
                            )
                        status_md = gr.Markdown(
                            value="_Enter a target path and click Run._",
                            label="Status",
                        )

                    with gr.Column(scale=1):
                        gr.Markdown(_INSTRUCTIONS_MD)

                log_box = gr.Textbox(
                    label="Agent Log",
                    lines=18,
                    max_lines=18,
                    interactive=False,
                    placeholder="Agent output will stream here...",
                    elem_classes=["status-box"],
                )

            # ── Tab 2: Report ─────────────────────────────────────────────────
            with gr.TabItem("📊 Report", id="report"):
                with gr.Row():
                    stats_md = gr.Markdown(value="_Run a scan to see results._")
                    dl_btn   = gr.File(
                        label="⬇️ Download HTML Report",
                        file_count="single",
                        interactive=False,
                        visible=True,
                    )

                report_html = gr.HTML(
                    value="<p style='color:#8b949e;text-align:center;padding:3rem'>Run a scan to see the security advisory.</p>",
                    label="Security Advisory",
                )

        # ── Event wiring ──────────────────────────────────────────────────────
        scan_btn.click(
            fn=scan_and_report,
            inputs=[target_input, use_llm_check],
            outputs=[status_md, log_box, report_html, stats_md, dl_btn],
        )

    return demo


def main() -> None:
    """Launch the WATCHDOG Gradio application."""
    demo = build_ui()
    print("=" * 60)
    print("🐕 WATCHDOG Web UI starting...")
    print(f"   Project root: {_PROJECT_ROOT}")
    print("   Open: http://localhost:7860")
    print("=" * 60)
    demo.launch(
        server_name="0.0.0.0",
        server_port=7860,
        share=False,
        show_error=True,
        favicon_path=None,
    )


if __name__ == "__main__":
    main()
