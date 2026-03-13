"""
scripts/test_pipeline.py
-------------------------
Smoke-test script for the WATCHDOG LangGraph pipeline.

Runs the full graph (all placeholder nodes) against a target directory
and prints a summary of the final state.

Usage:
    python scripts/test_pipeline.py
    python scripts/test_pipeline.py --target vuln_app/
    python scripts/test_pipeline.py --target . --verbose
"""

from __future__ import annotations

import argparse
import os
import sys
import time

# ── Ensure project root is importable ─────────────────────────────────────────
_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_SCRIPTS_DIR, ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from workflow.graph import watchdog_graph
from workflow.state import make_initial_state

console = Console()


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="WATCHDOG pipeline smoke test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--target",
        default="vuln_app/",
        help="Path to scan (default: vuln_app/)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print full final state dict",
    )
    return parser.parse_args()


def main() -> None:
    """Run the pipeline and print results."""
    args = parse_args()
    target = os.path.abspath(args.target) if not os.path.isabs(args.target) else args.target

    console.print(
        Panel.fit(
            f"[bold cyan]🐕 WATCHDOG Pipeline Test[/bold cyan]\n"
            f"Target: [yellow]{target}[/yellow]",
            border_style="cyan",
        )
    )

    # ── Run the graph ──────────────────────────────────────────────────────────
    initial_state = make_initial_state(target_path=target)

    console.print("\n[bold]Running LangGraph pipeline...[/bold]")
    t0 = time.perf_counter()

    final_state = watchdog_graph.invoke(initial_state)

    elapsed = time.perf_counter() - t0

    # ── Results table ──────────────────────────────────────────────────────────
    table = Table(title="Pipeline Results", border_style="cyan", show_header=True)
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")

    table.add_row("Target",            final_state.get("target_path", "—"))
    table.add_row("Findings",          str(len(final_state.get("findings", []))))
    table.add_row("Assessments",       str(len(final_state.get("assessments", []))))
    table.add_row("Threat assessments",str(len(final_state.get("threat_assessments", []))))
    table.add_row("Patches",           str(len(final_state.get("patches", []))))
    table.add_row("Verdicts",          str(len(final_state.get("verdicts", []))))
    table.add_row("Correction cycles", str(final_state.get("correction_count", 0)))
    table.add_row("Report length",     f"{len(final_state.get('final_report', ''))} chars")
    table.add_row("Elapsed",           f"{elapsed:.3f}s")

    console.print(table)

    # ── Report preview ─────────────────────────────────────────────────────────
    report = final_state.get("final_report", "")
    if report:
        console.print(Panel(report[:600] + ("..." if len(report) > 600 else ""),
                            title="Report Preview", border_style="green"))

    # ── Verbose dump ───────────────────────────────────────────────────────────
    if args.verbose:
        console.print("\n[bold]Full final state:[/bold]")
        import json
        try:
            console.print_json(json.dumps(final_state, default=str, indent=2))
        except Exception as exc:
            console.print(f"[red]Could not serialise state: {exc}[/red]")

    console.print("\n[bold green]✓ Pipeline completed successfully.[/bold green]")


if __name__ == "__main__":
    main()
