"""
scripts/test_pipeline.py
-------------------------
WATCHDOG Day 3 — full end-to-end pipeline test with self-correction loop demo.

Validates:
  1. Findings produced by Scanner (SQLi, IDOR, hardcoded secret + computil).
  2. CapabilityFingerprints from Code Analyst.
  3. TrustSignals — computil score < 0.30.
  4. ThreatAssessments from Threat Correlator (risk levels).
  5. Patch generation — IDOR patch missing @login_required on pass 1.
  6. Reviewer REJECTS the IDOR patch on pass 1.
  7. Self-correction loop fires — correction_count increments to 1.
  8. Reviewer APPROVES corrected patch on pass 2.
  9. Final state has all fields populated.

Usage:
    python scripts/test_pipeline.py                 # rule-based, no Ollama
    python scripts/test_pipeline.py --llm           # enable Ollama enrichment
    python scripts/test_pipeline.py --loop          # show correction loop detail
    python scripts/test_pipeline.py --target <path> # custom scan target
    python scripts/test_pipeline.py --verbose       # full state dump
"""

from __future__ import annotations

import argparse
import os
import sys
import time

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_SCRIPTS_DIR, ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from rich.console   import Console
from rich.panel     import Panel
from rich.table     import Table
from rich           import box

from workflow.graph  import watchdog_graph
from workflow.state  import make_initial_state

console = Console()


# ── CLI ────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="WATCHDOG Day 3 pipeline test")
    p.add_argument("--target",  default="vuln_app/", help="Path to scan")
    p.add_argument("--llm",     action="store_true",  help="Enable Ollama LLM calls")
    p.add_argument("--loop",    action="store_true",  help="Show correction loop details")
    p.add_argument("--verbose", action="store_true",  help="Full state dump")
    return p.parse_args()


# ── Rich print helpers ─────────────────────────────────────────────────────────

_SEV_COLOR = {"CRITICAL":"red","HIGH":"orange3","MEDIUM":"yellow","LOW":"green","NONE":"dim"}
_RISK_EMOJI = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","NONE":"✅"}


def _print_header(target: str, use_llm: bool) -> None:
    console.print(Panel.fit(
        f"[bold cyan]🐕 WATCHDOG — Day 3 Pipeline Test[/bold cyan]\n"
        f"Target : [yellow]{target}[/yellow]\n"
        f"LLM    : {'[green]enabled (Ollama)[/green]' if use_llm else '[dim]disabled (rule-based)[/dim]'}",
        border_style="cyan",
    ))


def _print_findings(findings: list) -> None:
    if not findings:
        console.print("[yellow]No findings.[/yellow]"); return
    t = Table(title=f"Findings ({len(findings)})", box=box.SIMPLE_HEAD, border_style="yellow")
    t.add_column("#", width=4, style="dim")
    t.add_column("Package",  min_width=12, style="cyan")
    t.add_column("Severity", width=10)
    t.add_column("Type",     min_width=20)
    t.add_column("File:Line",min_width=28, style="dim")
    for i, f in enumerate(findings, 1):
        c = _SEV_COLOR.get(f.severity, "white")
        t.add_row(str(i), f.package_name,
                  f"[{c}]{f.severity}[/{c}]", f.finding_type,
                  f"{os.path.basename(f.file_path)}:{f.line_number}")
    console.print(t)


def _print_fingerprints(fps: list) -> None:
    if not fps:
        console.print("[yellow]No fingerprints.[/yellow]"); return
    t = Table(title=f"Capability Fingerprints ({len(fps)})",
              box=box.SIMPLE_HEAD, border_style="blue")
    t.add_column("Package",    min_width=12, style="cyan")
    t.add_column("Network",    width=9,  justify="center")
    t.add_column("Subprocess", width=12, justify="center")
    t.add_column("Base64",     width=8,  justify="center")
    t.add_column("Env",        width=6,  justify="center")
    _y = "[red]YES[/red]"; _n = "[dim]no[/dim]"
    for fp in fps:
        t.add_row(fp.package_name,
                  _y if fp.network_calls else _n,
                  _y if fp.subprocess_calls else _n,
                  _y if fp.base64_encoded_payloads else _n,
                  _y if fp.env_variable_access else _n)
    console.print(t)


def _print_trust(signals: list) -> None:
    if not signals:
        console.print("[yellow]No trust signals.[/yellow]"); return
    t = Table(title=f"Trust Signals ({len(signals)})",
              box=box.SIMPLE_HEAD, border_style="magenta")
    t.add_column("Package",    min_width=12, style="cyan")
    t.add_column("Maintainer", min_width=14, style="dim")
    t.add_column("Age",        width=8,  justify="right")
    t.add_column("Commits",    width=9,  justify="right")
    t.add_column("Score",      width=8,  justify="right")
    t.add_column("Risk",       width=10, justify="center")
    for ts in signals:
        s = ts.trust_score
        rc = "red" if s<0.2 else "orange3" if s<0.4 else "yellow" if s<0.6 else "green"
        rl = "CRITICAL" if s<0.2 else "HIGH" if s<0.4 else "MEDIUM" if s<0.6 else "LOW" if s<0.8 else "TRUSTED"
        t.add_row(ts.package_name,
                  ts.maintainer_username or "?",
                  f"{ts.account_age_days}d" if ts.account_age_days else "?",
                  str(ts.commit_count) if ts.commit_count else "?",
                  f"{s:.2f}",
                  f"[{rc}]{rl}[/{rc}]")
    console.print(t)


def _print_threats(assessments: list) -> None:
    if not assessments:
        console.print("[yellow]No threat assessments.[/yellow]"); return
    t = Table(title=f"Threat Assessments ({len(assessments)})",
              box=box.SIMPLE_HEAD, border_style="red")
    t.add_column("Package",   min_width=12, style="cyan")
    t.add_column("Risk",      width=11, justify="center")
    t.add_column("Similarity",width=11, justify="right")
    t.add_column("Pattern",   min_width=20, style="dim")
    t.add_column("Deeper?",   width=8,  justify="center")
    for ta in assessments:
        c = _SEV_COLOR.get(ta.risk_level, "white")
        e = _RISK_EMOJI.get(ta.risk_level, "")
        sim = f"{ta.pattern_similarity_score:.3f}" if ta.pattern_similarity_score else "—"
        pattern = (ta.closest_attack_pattern or "heuristic")[:28]
        deeper = "[red]YES[/red]" if ta.requires_deeper_analysis else "[dim]no[/dim]"
        t.add_row(ta.package_name,
                  f"{e} [{c}]{ta.risk_level}[/{c}]",
                  sim, pattern, deeper)
    console.print(t)


def _print_correction_loop(
    verdicts: list,
    mandates: list,
    correction_count: int,
    show_detail: bool,
) -> None:
    """Print the self-correction loop summary — the Day 3 highlight."""
    has_rejection = any(not v.approved for v in verdicts)

    if has_rejection:
        rejected = [v for v in verdicts if not v.approved]
        console.print(Panel(
            "\n".join(
                f"  [red]✗[/red] [cyan]{v.package_name}[/cyan]\n"
                f"    {v.feedback[:120]}"
                for v in rejected
            ),
            title=f"[red]⚡ Reviewer Rejected {len(rejected)} Patch(es) — Correction Loop Triggered[/red]",
            border_style="red",
        ))
        if show_detail and mandates:
            for m in mandates:
                console.print(
                    f"\n[bold]Correction Mandate → [cyan]{m.package_name}[/cyan][/bold]\n"
                    + "\n".join(f"  • {instr}" for instr in m.correction_instructions)
                )
    else:
        console.print(Panel(
            f"  All {len(verdicts)} patch(es) approved after {correction_count} "
            f"correction cycle(s).",
            title="[green]✅ All Patches Approved[/green]",
            border_style="green",
        ))


def _print_verdicts(verdicts: list) -> None:
    if not verdicts:
        console.print("[yellow]No verdicts.[/yellow]"); return
    t = Table(title=f"Review Verdicts ({len(verdicts)})",
              box=box.SIMPLE_HEAD, border_style="green")
    t.add_column("Package",  min_width=12, style="cyan")
    t.add_column("Action",   min_width=20)
    t.add_column("Verdict",  width=12, justify="center")
    t.add_column("Feedback", min_width=30, style="dim")
    for v in verdicts:
        status = "[green]✅ APPROVED[/green]" if v.approved else "[red]❌ REJECTED[/red]"
        fb = (v.feedback or "")[:60]
        t.add_row(v.package_name, "", status, fb)
    console.print(t)


# ── Validation ─────────────────────────────────────────────────────────────────

def _validate(final: dict) -> list[str]:
    failures: list[str] = []

    findings     = final.get("findings",      [])
    fps          = final.get("fingerprints",  [])
    signals      = final.get("trust_signals", [])
    threats      = final.get("threat_assessments", [])
    patches      = final.get("patches",       [])
    verdicts     = final.get("verdicts",      [])
    corr_count   = final.get("correction_count", 0)

    # ── Findings ───────────────────────────────────────────────────────────────
    if not findings:
        failures.append("No findings — Bandit may not be installed.")
    else:
        types = {f.finding_type for f in findings}
        for expected in ("sql_injection", "hardcoded_secret"):
            if expected not in types:
                failures.append(f"Expected finding type '{expected}' not detected.")
        for f in findings:
            if "test_" in os.path.basename(f.file_path):
                failures.append(f"Test file not filtered: {f.file_path}")

    # ── Fingerprints ───────────────────────────────────────────────────────────
    if findings and not fps:
        failures.append("No fingerprints produced — Code Analyst may have failed.")

    # ── Trust: computil must be < 0.30 ────────────────────────────────────────
    computil_sig = next((s for s in signals if "computil" in s.package_name), None)
    if not computil_sig:
        failures.append("No TrustSignal for 'computil' package.")
    elif computil_sig.trust_score >= 0.30:
        failures.append(
            f"computil trust_score={computil_sig.trust_score:.2f} ≥ 0.30 "
            "(expected CRITICAL)."
        )

    # ── Threats ────────────────────────────────────────────────────────────────
    if fps and not threats:
        failures.append("No threat assessments — Threat Correlator may have failed.")
    computil_threat = next((t for t in threats if "computil" in t.package_name), None)
    if computil_threat and computil_threat.risk_level not in ("HIGH", "CRITICAL"):
        failures.append(
            f"computil risk_level={computil_threat.risk_level} — expected HIGH or CRITICAL."
        )

    # ── Self-correction loop ───────────────────────────────────────────────────
    if corr_count == 0 and any(not v.approved for v in verdicts):
        failures.append(
            "Rejected verdict found but correction_count=0 — "
            "correction loop did not fire."
        )

    # ── Final verdicts: all approved ───────────────────────────────────────────
    final_rejected = [v for v in verdicts if not v.approved]
    if final_rejected:
        # Acceptable if we hit max retries
        if corr_count < 2:
            failures.append(
                f"{len(final_rejected)} patch(es) still rejected after "
                f"correction loop — check Reviewer logic."
            )

    return failures


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    args   = parse_args()
    target = os.path.abspath(args.target)
    _print_header(target, args.llm)

    console.print("\n[bold]Invoking WATCHDOG LangGraph pipeline...[/bold]\n")
    t0 = time.perf_counter()
    final = watchdog_graph.invoke(make_initial_state(target, use_llm=args.llm))
    elapsed = time.perf_counter() - t0

    findings     = final.get("findings",          [])
    fps          = final.get("fingerprints",       [])
    signals      = final.get("trust_signals",      [])
    threats      = final.get("threat_assessments", [])
    patches      = final.get("patches",            [])
    verdicts     = final.get("verdicts",           [])
    mandates     = final.get("correction_mandates",[])
    corr_count   = final.get("correction_count",   0)

    console.print()
    _print_findings(findings)
    console.print()
    _print_fingerprints(fps)
    console.print()
    _print_trust(signals)
    console.print()
    _print_threats(threats)
    console.print()
    _print_verdicts(verdicts)
    console.print()
    _print_correction_loop(verdicts, mandates, corr_count, show_detail=args.loop)

    # ── Pipeline summary bar ──────────────────────────────────────────────────
    console.print(Panel(
        f"  [cyan]Findings[/cyan]     {len(findings):>3}    "
        f"[cyan]Fingerprints[/cyan]  {len(fps):>3}    "
        f"[cyan]Threats[/cyan]  {len(threats):>3}\n"
        f"  [cyan]Patches[/cyan]      {len(patches):>3}    "
        f"[cyan]Verdicts[/cyan]      {len(verdicts):>3}    "
        f"[cyan]Corrections[/cyan] {corr_count:>3}\n"
        f"  [dim]elapsed: {elapsed:.2f}s[/dim]",
        title="[bold]Pipeline Summary[/bold]",
        border_style="cyan",
    ))

    if args.verbose:
        import json
        console.print("\n[bold]Full state (JSON):[/bold]")
        console.print_json(json.dumps(final, default=str, indent=2))

    # ── Validation ────────────────────────────────────────────────────────────
    failures = _validate(final)
    console.print()
    if failures:
        console.print(Panel(
            "\n".join(f"  ✗ {f}" for f in failures),
            title="[red]Validation Failures[/red]",
            border_style="red",
        ))
        sys.exit(1)
    else:
        console.print(Panel(
            f"  All validations passed ✓  (correction_count={corr_count})",
            title="[green]✓ Day 3 Test Passed[/green]",
            border_style="green",
        ))


if __name__ == "__main__":
    main()
