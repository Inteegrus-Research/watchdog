"""
agents/reporter.py
-------------------
WATCHDOG Report Generator Agent — Day 4 full implementation.

Pipeline role:
  - Consumes the complete WatchdogState at the end of the pipeline.
  - Renders both a Markdown advisory and a self-contained dark-mode HTML report
    using Jinja2 templates from the templates/ directory.
  - Saves the HTML file to reports/<timestamp>/watchdog_report.html.
  - Returns state["final_report"] = Markdown string (for API consumers)
    and state["final_report_html"] = HTML string (for the Gradio web UI).

Public API:
  generate_report(state) -> tuple[str, str]   → (markdown, html)
  run_reporter(state)    -> dict               → LangGraph node
"""

from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path

_AGENT_DIR    = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_AGENT_DIR, ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# ── Logging ────────────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[reporter {ts}] {msg}")


# ── Markdown report (simple, no Jinja2 required) ──────────────────────────────

def _render_markdown(state: dict) -> str:
    """Generate a clean Markdown advisory from state — no external dependencies."""
    findings          = state.get("findings",          [])
    threat_assessments= state.get("threat_assessments", [])
    patches           = state.get("patches",            [])
    verdicts          = state.get("verdicts",           [])
    trust_signals     = state.get("trust_signals",      [])
    correction_count  = state.get("correction_count",   0)
    target_path       = state.get("target_path",        "unknown")
    scan_ts           = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Build lookups
    ta_map = {ta.package_name: ta for ta in threat_assessments}
    ts_map = {ts.package_name: ts for ts in trust_signals}
    v_map  = {}
    for v in verdicts:
        v_map[v.package_name] = v  # last verdict per package

    crit  = [ta for ta in threat_assessments if ta.risk_level == "CRITICAL"]
    high  = [ta for ta in threat_assessments if ta.risk_level == "HIGH"]
    med   = [ta for ta in threat_assessments if ta.risk_level == "MEDIUM"]

    lines: list[str] = [
        "# 🐕 WATCHDOG Security Advisory",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Target** | `{target_path}` |",
        f"| **Scan time** | {scan_ts} |",
        f"| **Total findings** | {len(findings)} |",
        f"| **CRITICAL packages** | {len(crit)} |",
        f"| **HIGH packages** | {len(high)} |",
        f"| **Patches generated** | {len(patches)} |",
        f"| **Correction cycles** | {correction_count} |",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
    ]

    if crit:
        lines.append(f"> ⛔ **CRITICAL** — {len(crit)} package(s) consistent with active supply chain attack. **Immediate action required.**")
    elif high:
        lines.append(f"> 🔴 **HIGH** — {len(high)} package(s) with high-severity findings.")
    elif med:
        lines.append(f"> 🟡 **MEDIUM** — {len(med)} package(s) with medium-severity findings.")
    else:
        lines.append("> ✅ **CLEAN** — No significant threats detected.")

    lines += ["", "---", "", "## Threat Assessments", ""]
    for ta in threat_assessments:
        ts   = ts_map.get(ta.package_name)
        risk_icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","NONE":"✅"}.get(ta.risk_level,"❓")
        lines += [
            f"### {risk_icon} `{ta.package_name}` — {ta.risk_level}",
            "",
            f"**Closest attack pattern:** {ta.closest_attack_pattern or 'heuristic'}  ",
            f"**Pattern similarity:** {ta.pattern_similarity_score:.3f}  " if ta.pattern_similarity_score else "",
            f"**Requires deeper analysis:** {'Yes ⚑' if ta.requires_deeper_analysis else 'No'}",
            "",
            f"**Code analysis:** {ta.exploit_assessment_summary}",
            "",
            f"**Maintainer trust:** {ta.trust_signal_summary}",
            "",
        ]
        if ts and ts.anomalies:
            lines.append("**Anomalies:**")
            for a in ts.anomalies[:4]:
                lines.append(f"- ⚠ {a}")
            lines.append("")

        lines += [f"**Reasoning:** _{ta.final_reasoning}_", "", "---", ""]

    lines += ["## Findings Detail", ""]
    for i, f in enumerate(findings, 1):
        sev_icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(f.severity,"❓")
        lines += [
            f"### Finding {i}: {sev_icon} `{f.finding_type}` in `{f.package_name}`",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **File** | `{f.file_path}:{f.line_number}` |",
            f"| **Severity** | {f.severity} |",
            f"| **Type** | {f.finding_type} |",
            "",
            f"**Description:** {f.description}",
            "",
        ]
        if f.code_snippet:
            lines += ["```python", f.code_snippet, "```", ""]

    lines += ["## Remediation Proposals", ""]
    for patch in patches:
        v = v_map.get(patch.package_name)
        status = "✅ Approved" if (v and v.approved) else "❌ Rejected"
        lines += [
            f"### `{patch.package_name}` — `{patch.proposed_action}` ({status})",
            "",
            f"**Confidence:** {patch.confidence:.0%}  ",
            f"**Rationale:** {patch.rationale}",
            "",
        ]
        if patch.patch_diff:
            lines += ["```diff", patch.patch_diff, "```", ""]

    if correction_count > 0:
        lines += [
            "---",
            "",
            "## Self-Correction Loop",
            "",
            f"The Reviewer Agent rejected patches during **{correction_count}** correction cycle(s).  ",
            "The Patch Writer re-generated improved versions which were subsequently approved.",
            "",
        ]

    lines += [
        "---",
        "",
        f"*Generated by WATCHDOG v1.0 · {scan_ts}*",
    ]

    return "\n".join(lines)


# ── HTML report via Jinja2 ─────────────────────────────────────────────────────

def _render_html(state: dict, markdown_report: str, duration_s: float = 0.0) -> str:
    """
    Render the dark-mode HTML report via the Jinja2 template.
    Falls back to a minimal inline HTML if Jinja2 is not installed.
    """
    template_dir = os.path.join(_PROJECT_ROOT, "templates")

    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
        env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html"]),
        )
        template = env.get_template("report.html.j2")

        ctx = {
            "target_path":        state.get("target_path", "unknown"),
            "scan_timestamp":     datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "scan_duration_s":    duration_s,
            "findings":           state.get("findings",           []),
            "fingerprints":       state.get("fingerprints",       []),
            "trust_signals":      state.get("trust_signals",      []),
            "threat_assessments": state.get("threat_assessments", []),
            "patches":            state.get("patches",            []),
            "verdicts":           state.get("verdicts",           []),
            "mandates":           state.get("correction_mandates", []),
            "correction_count":   state.get("correction_count",   0),
            "final_report_md":    markdown_report,
        }

        html = template.render(**ctx)
        _log("HTML report rendered via Jinja2 template.")
        return html

    except ImportError:
        _log("WARN: Jinja2 not installed — generating minimal HTML fallback.")
        return _html_fallback(state, markdown_report)
    except Exception as exc:  # noqa: BLE001
        _log(f"WARN: Jinja2 render error: {exc} — using minimal HTML fallback.")
        return _html_fallback(state, markdown_report)


def _html_fallback(state: dict, markdown: str) -> str:
    """Minimal self-contained HTML when Jinja2 is unavailable."""
    findings  = state.get("findings",    [])
    threats   = state.get("threat_assessments", [])
    patches   = state.get("patches",     [])
    verdicts  = state.get("verdicts",    [])
    target    = state.get("target_path", "unknown")
    corr      = state.get("correction_count", 0)

    v_map = {v.package_name: v for v in verdicts}

    badge_colors = {
        "CRITICAL": "#ff4444", "HIGH": "#ff7b00",
        "MEDIUM": "#f0c000",   "LOW":  "#3fb950", "NONE": "#8b949e",
    }

    rows = ""
    for ta in threats:
        c = badge_colors.get(ta.risk_level, "#8b949e")
        rows += (
            f"<tr><td><code>{ta.package_name}</code></td>"
            f"<td><span style='color:{c};font-weight:700'>{ta.risk_level}</span></td>"
            f"<td>{ta.pattern_similarity_score:.3f if ta.pattern_similarity_score else '—'}</td></tr>\n"
        )

    patch_rows = ""
    for p in patches:
        v = v_map.get(p.package_name)
        vstatus = ("✅" if v and v.approved else "❌") if v else "—"
        patch_rows += (
            f"<tr><td><code>{p.package_name}</code></td>"
            f"<td><code>{p.proposed_action}</code></td>"
            f"<td>{vstatus}</td>"
            f"<td style='font-size:.82rem;color:#8b949e'>{p.rationale[:80]}…</td></tr>\n"
        )

    md_escaped = markdown.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>WATCHDOG Report</title>
<style>
body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2rem;line-height:1.6}}
h1{{color:#58a6ff;margin-bottom:.5rem}}h2{{color:#58a6ff;margin:1.5rem 0 .7rem;border-bottom:1px solid #30363d;padding-bottom:.3rem}}
table{{border-collapse:collapse;width:100%;margin:.8rem 0}}
th{{background:#161b22;color:#8b949e;font-size:.78rem;text-transform:uppercase;padding:.5rem .9rem;text-align:left;border-bottom:2px solid #30363d}}
td{{padding:.5rem .9rem;border-bottom:1px solid #30363d;font-size:.87rem}}
tr:hover td{{background:#161b22}}code{{background:#010409;padding:.1em .4em;border-radius:3px}}
pre{{background:#010409;padding:1rem;border-radius:6px;overflow:auto;font-size:.8rem;margin:.8rem 0}}
</style></head>
<body>
<h1>🐕 WATCHDOG Security Advisory</h1>
<p style="color:#8b949e">Target: <code>{target}</code> &nbsp;|&nbsp; Findings: {len(findings)} &nbsp;|&nbsp; Corrections: {corr}</p>
<h2>Threat Assessments</h2>
<table><thead><tr><th>Package</th><th>Risk</th><th>Similarity</th></tr></thead>
<tbody>{rows}</tbody></table>
<h2>Patch Proposals</h2>
<table><thead><tr><th>Package</th><th>Action</th><th>Status</th><th>Rationale</th></tr></thead>
<tbody>{patch_rows}</tbody></table>
<h2>Full Report (Markdown)</h2>
<pre>{md_escaped}</pre>
</body></html>"""


# ── File saving ────────────────────────────────────────────────────────────────

def _save_report(html: str, target_path: str) -> str:
    """
    Save the HTML report to reports/<timestamp>/watchdog_report.html.

    Returns
    -------
    str : Absolute path to the saved file.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = Path(_PROJECT_ROOT) / "reports" / timestamp
    report_dir.mkdir(parents=True, exist_ok=True)

    report_path = report_dir / "watchdog_report.html"
    report_path.write_text(html, encoding="utf-8")

    # Also write a symlink / copy at the project root for easy access
    latest_path = Path(_PROJECT_ROOT) / "watchdog_report.html"
    latest_path.write_text(html, encoding="utf-8")

    return str(report_path)


# ── Public API ─────────────────────────────────────────────────────────────────

def generate_report(state: dict, duration_s: float = 0.0) -> tuple[str, str]:
    """
    Generate the WATCHDOG security advisory in both Markdown and HTML.

    Parameters
    ----------
    state      : WatchdogState dict with all pipeline results.
    duration_s : Total pipeline wall-clock time (optional, for the report header).

    Returns
    -------
    (markdown_str, html_str)
    """
    target = state.get("target_path", "unknown")
    n_findings = len(state.get("findings", []))
    n_threats  = len(state.get("threat_assessments", []))
    corr       = state.get("correction_count", 0)

    _log(f"Generating report — target={target}  findings={n_findings}  "
         f"threats={n_threats}  correction_count={corr}")

    markdown = _render_markdown(state)
    html     = _render_html(state, markdown, duration_s)

    # Save to disk
    try:
        saved_path = _save_report(html, target)
        _log(f"Report saved: {saved_path}")
        _log(f"Quick link  : {_PROJECT_ROOT}/watchdog_report.html")
    except Exception as exc:  # noqa: BLE001
        _log(f"WARN: Could not save report to disk: {exc}")

    _log(f"Report complete — Markdown: {len(markdown)} chars, HTML: {len(html)} chars")
    return markdown, html


# ── LangGraph node ─────────────────────────────────────────────────────────────

def run_reporter(state: dict) -> dict:
    """
    LangGraph node — generates the final security advisory and writes it to state.

    Updates:
      state["final_report"]      = Markdown string
      state["final_report_html"] = HTML string
    """
    _log(f"Reporter node invoked — target: {state.get('target_path', 'unknown')}")

    duration_s = state.get("_pipeline_duration_s", 0.0)
    markdown, html = generate_report(state, duration_s)

    return {
        "final_report":      markdown,
        "final_report_html": html,
    }


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json as _json
    from agents.scanner           import scan
    from agents.code_analyst      import analyse_findings
    from agents.trust_analyst     import analyse_trust
    from agents.threat_correlator import correlate
    from agents.patch_writer      import write_patches
    from agents.reviewer          import review_all

    target   = sys.argv[1] if len(sys.argv) > 1 else "vuln_app/"
    findings = scan(target)
    fps      = analyse_findings(findings)
    signals  = analyse_trust(findings, use_llm=False)
    threats  = correlate(fps, signals)
    patches  = write_patches(findings, threats, signals, [], [], 0)
    verdicts, mandates = review_all(patches, findings, use_llm=False, correction_count=0)

    state = {
        "target_path": target,
        "findings": findings, "fingerprints": fps,
        "trust_signals": signals, "threat_assessments": threats,
        "patches": patches, "verdicts": verdicts, "correction_mandates": mandates,
        "correction_count": 1 if any(not v.approved for v in verdicts) else 0,
    }

    md, html = generate_report(state)
    print(f"\n{'─'*60}")
    print(f"Markdown ({len(md)} chars):")
    print(md[:600])
    print(f"\nHTML report: {_PROJECT_ROOT}/watchdog_report.html")
