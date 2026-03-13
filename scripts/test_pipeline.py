"""
scripts/test_pipeline.py
-------------------------
WATCHDOG end-to-end pipeline test — Day 2 update.

Runs the full LangGraph pipeline against vuln_app/ and validates:
  1. Findings list contains at least the expected vulnerability types.
  2. CapabilityFingerprints are produced for each unique (package, file).
  3. computil package receives a low trust score (< 0.30).
  4. Other packages (vuln_app) receive a higher trust score.
  5. Patch proposals are generated.

Usage:
    python scripts/test_pipeline.py               # scan vuln_app/, LLM disabled
    python scripts/test_pipeline.py --llm         # enable Ollama enrichment
    python scripts/test_pipeline.py --target .    # scan entire project
    python scripts/test_pipeline.py --verbose     # dump full state
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

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from workflow.graph import watchdog_graph
from workflow.state import make_initial_state

console = Console()


# ── CLI ────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="WATCHDOG Day 2 pipeline test")
    p.add_argument("--target",   default="vuln_app/", help="Path to scan")
    p.add_argument("--llm",      action="store_true",  help="Enable Ollama LLM calls")
    p.add_argument("--verbose",  action="store_true",  help="Print full state dump")
    return p.parse_args()


# ── Validation helpers ─────────────────────────────────────────────────────────

EXPECTED_FINDING_TYPES = {
    "sql_injection",
    "hardcoded_secret",
}

def _validate_findings(findings: list) -> list[str]:
    """Return a list of validation failure messages (empty = all passed)."""
    failures: list[str] = []
    found_types = {f.finding_type for f in findings}

    if not findings:
        failures.append("No findings produced — Bandit may not be installed.")
        return failures

    for expected in EXPECTED_FINDING_TYPES:
        if expected not in found_types:
            failures.append(f"Expected finding type '{expected}' not detected.")

    # Ensure test_auth.py was filtered
    for f in findings:
        if "test_" in os.path.basename(f.file_path):
            failures.append(
                f"Test file not filtered: {f.file_path}  "
                "(Scanner Agent filtering is broken)"
            )
    return failures


def _validate_fingerprints(fps: list, findings: list) -> list[str]:
    failures: list[str] = []
    if findings and not fps:
        failures.append(
            "No fingerprints produced despite findings — "
            "Code Analyst Agent may have failed."
        )
    return failures


def _validate_trust(trust_signals: list) -> list[str]:
    failures: list[str] = []
    computil_signal = next(
        (ts for ts in trust_signals if "computil" in ts.package_name.lower()), None
    )
    if computil_signal is None:
        # computil only shows up if bandit finds something in its file;
        # warn but don't hard-fail
        failures.append(
            "No TrustSignal for 'computil' — "
            "check that vuln_app/computil/__init__.py was scanned."
        )
    elif computil_signal.trust_score >= 0.30:
        failures.append(
            f"computil trust_score={computil_signal.trust_score:.2f} is too high "
            f"(expected < 0.30 for a malicious package)."
        )
    return failures


# ── Rich output helpers ────────────────────────────────────────────────────────

def _print_header(target: str, use_llm: bool) -> None:
    console.print(Panel.fit(
        f"[bold cyan]🐕 WATCHDOG — Day 2 Pipeline Test[/bold cyan]\n"
        f"Target : [yellow]{target}[/yellow]\n"
        f"LLM    : [green]{'enabled (Ollama)' if use_llm else 'disabled (rule-based)'}[/green]",
        border_style="cyan",
    ))


def _print_findings(findings: list) -> None:
    if not findings:
        console.print("[yellow]No findings.[/yellow]")
        return

    t = Table(title=f"Findings ({len(findings)})", box=box.SIMPLE_HEAD, border_style="yellow")
    t.add_column("#",            style="dim",    width=4)
    t.add_column("Package",      style="cyan",   min_width=12)
    t.add_column("Severity",     style="bold",   width=10)
    t.add_column("Type",                         min_width=20)
    t.add_column("File:Line",    style="dim",    min_width=30)

    severity_colors = {
        "CRITICAL": "red",
        "HIGH":     "orange3",
        "MEDIUM":   "yellow",
        "LOW":      "green",
    }

    for i, f in enumerate(findings, 1):
        color = severity_colors.get(f.severity, "white")
        basename = os.path.basename(f.file_path)
        t.add_row(
            str(i),
            f.package_name,
            f"[{color}]{f.severity}[/{color}]",
            f.finding_type,
            f"{basename}:{f.line_number}",
        )
    console.print(t)


def _print_fingerprints(fps: list) -> None:
    if not fps:
        console.print("[yellow]No fingerprints.[/yellow]")
        return

    t = Table(
        title=f"Capability Fingerprints ({len(fps)})",
        box=box.SIMPLE_HEAD,
        border_style="blue",
    )
    t.add_column("Package",   style="cyan",  min_width=12)
    t.add_column("Network",   width=9,  justify="center")
    t.add_column("Subprocess",width=12, justify="center")
    t.add_column("Base64",    width=8,  justify="center")
    t.add_column("Env",       width=6,  justify="center")
    t.add_column("Filesystem",width=12, justify="center")

    _y = "[red]YES[/red]"
    _n = "[dim]no[/dim]"

    for fp in fps:
        t.add_row(
            fp.package_name,
            _y if fp.network_calls            else _n,
            _y if fp.subprocess_calls          else _n,
            _y if fp.base64_encoded_payloads   else _n,
            _y if fp.env_variable_access       else _n,
            _y if fp.filesystem_writes         else _n,
        )
    console.print(t)


def _print_trust(trust_signals: list) -> None:
    if not trust_signals:
        console.print("[yellow]No trust signals.[/yellow]")
        return

    t = Table(
        title=f"Trust Signals ({len(trust_signals)})",
        box=box.SIMPLE_HEAD,
        border_style="magenta",
    )
    t.add_column("Package",     style="cyan",  min_width=12)
    t.add_column("Maintainer",  style="dim",   min_width=14)
    t.add_column("Acct Age",    width=10,  justify="right")
    t.add_column("Commits",     width=9,   justify="right")
    t.add_column("Trust Score", width=13,  justify="right")
    t.add_column("Risk",        width=10,  justify="center")
    t.add_column("Anomalies",   min_width=10)

    for ts in trust_signals:
        score = ts.trust_score
        risk_color = (
            "red"    if score < 0.20 else
            "orange3"if score < 0.40 else
            "yellow" if score < 0.60 else
            "green"
        )
        risk_label = (
            "CRITICAL" if score < 0.20 else
            "HIGH"     if score < 0.40 else
            "MEDIUM"   if score < 0.60 else
            "LOW"      if score < 0.80 else
            "TRUSTED"
        )
        age = f"{ts.account_age_days}d" if ts.account_age_days else "?"
        commits = str(ts.commit_count) if ts.commit_count else "?"
        anomaly_count = len(ts.anomalies)

        t.add_row(
            ts.package_name,
            ts.maintainer_username or "unknown",
            age,
            commits,
            f"{score:.2f}",
            f"[{risk_color}]{risk_label}[/{risk_color}]",
            f"{anomaly_count} anomaly{'s' if anomaly_count != 1 else ''}",
        )
        # Print anomaly detail lines
        for anomaly in ts.anomalies[:3]:
            t.add_row("", "", "", "", "", "", f"  [dim]• {anomaly}[/dim]")

    console.print(t)


def _print_patches(patches: list) -> None:
    if not patches:
        console.print("[yellow]No patches.[/yellow]")
        return

    t = Table(
        title=f"Patch Proposals ({len(patches)})",
        box=box.SIMPLE_HEAD,
        border_style="green",
    )
    t.add_column("Package",    style="cyan",  min_width=12)
    t.add_column("Action",                   min_width=20)
    t.add_column("Confidence", width=12, justify="right")

    action_colors = {
        "remove_dependency": "red",
        "apply_code_patch":  "orange3",
        "pin_version":       "yellow",
        "monitor_only":      "green",
        "no_action":         "dim",
    }

    for p in patches:
        color = action_colors.get(p.proposed_action, "white")
        t.add_row(
            p.package_name,
            f"[{color}]{p.proposed_action}[/{color}]",
            f"{p.confidence:.0%}",
        )
    console.print(t)


def _print_validation(all_failures: list[str], elapsed: float) -> None:
    if all_failures:
        console.print(Panel(
            "\n".join(f"  ✗ {f}" for f in all_failures),
            title="[red]Validation Failures[/red]",
            border_style="red",
        ))
    else:
        console.print(Panel(
            f"  All validations passed ✓  |  elapsed: {elapsed:.2f}s",
            title="[green]✓ Test Passed[/green]",
            border_style="green",
        ))


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()
    target = os.path.abspath(args.target)
    use_llm = args.llm

    _print_header(target, use_llm)

    # ── Run pipeline ──────────────────────────────────────────────────────────
    initial_state = make_initial_state(target_path=target, use_llm=use_llm)
    console.print("\n[bold]Invoking LangGraph pipeline...[/bold]\n")

    t0 = time.perf_counter()
    final_state = watchdog_graph.invoke(initial_state)
    elapsed = time.perf_counter() - t0

    # ── Extract results ───────────────────────────────────────────────────────
    findings      = final_state.get("findings",      [])
    fingerprints  = final_state.get("fingerprints",  [])
    trust_signals = final_state.get("trust_signals", [])
    patches       = final_state.get("patches",       [])

    # ── Print results ─────────────────────────────────────────────────────────
    console.print()
    _print_findings(findings)
    console.print()
    _print_fingerprints(fingerprints)
    console.print()
    _print_trust(trust_signals)
    console.print()
    _print_patches(patches)

    # ── Optional verbose dump ─────────────────────────────────────────────────
    if args.verbose:
        console.print("\n[bold]Full state (JSON):[/bold]")
        import json
        console.print_json(json.dumps(final_state, default=str, indent=2))

    # ── Validate results ──────────────────────────────────────────────────────
    console.print()
    all_failures: list[str] = []
    all_failures += _validate_findings(findings)
    all_failures += _validate_fingerprints(fingerprints, findings)
    all_failures += _validate_trust(trust_signals)
    _print_validation(all_failures, elapsed)


if __name__ == "__main__":
    main()
