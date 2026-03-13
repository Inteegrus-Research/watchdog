"""
agents/scanner.py
-----------------
WATCHDOG Scanner Agent — Day 2 full implementation.

Pipeline role:
  - Entry point of the LangGraph pipeline.
  - Runs Bandit static analysis over the target directory.
  - Filters out test files so decoy credentials are not false-positives.
  - Converts every Bandit issue into a typed FindingRecord.
  - Returns the updated state dict with state["findings"] populated.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from typing import Any

# Ensure project root is importable when running directly
_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_AGENT_DIR, ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from schemas.models import FindingRecord
from utils.file_utils import is_test_file

# ── Logging helper ─────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[scanner {ts}] {msg}")


# ── Bandit severity / test-id → FindingRecord type mapping ───────────────────

_BANDIT_ID_TO_TYPE: dict[str, str] = {
    "B105": "hardcoded_secret",
    "B106": "hardcoded_secret",
    "B107": "hardcoded_secret",
    "B108": "hardcoded_secret",
    "B608": "sql_injection",
    "B602": "subprocess_exec",
    "B603": "subprocess_exec",
    "B604": "subprocess_exec",
    "B605": "subprocess_exec",
    "B606": "subprocess_exec",
    "B607": "subprocess_exec",
    "B312": "network_call",
    "B321": "network_call",
    "B201": "other",
    "B101": "other",
    "B110": "other",
}

_BANDIT_NAME_TO_TYPE: dict[str, str] = {
    "hardcoded_password_string": "hardcoded_secret",
    "hardcoded_password_funcarg": "hardcoded_secret",
    "hardcoded_password_default": "hardcoded_secret",
    "hardcoded_sql_expressions": "sql_injection",
    "subprocess_popen_with_shell_equals_true": "subprocess_exec",
    "start_process_with_a_shell": "subprocess_exec",
    "start_process_with_no_shell": "subprocess_exec",
    "socket": "network_call",
    "ftplib": "network_call",
    "telnetlib": "network_call",
}

_SEVERITY_MAP: dict[str, str] = {
    "HIGH":   "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW":    "LOW",
}


# ── Core helpers ───────────────────────────────────────────────────────────────

def _infer_package_name(file_path: str, target_path: str) -> str:
    """Derive a logical package name from a file's path relative to the target root."""
    try:
        rel = os.path.relpath(file_path, target_path)
        parts = rel.replace("\\", "/").split("/")
        if len(parts) >= 2:
            return parts[0]
        return os.path.basename(target_path.rstrip("/\\")) or "unknown"
    except ValueError:
        return "unknown"


def _map_finding_type(test_id: str, test_name: str) -> str:
    """Map a Bandit test_id / test_name to our internal finding_type literal."""
    if test_id in _BANDIT_ID_TO_TYPE:
        return _BANDIT_ID_TO_TYPE[test_id]
    for key, ftype in _BANDIT_NAME_TO_TYPE.items():
        if key in test_name.lower():
            return ftype
    return "other"


def _bandit_to_finding(issue: dict[str, Any], target_path: str) -> "FindingRecord | None":
    """Convert one Bandit issue dict into a FindingRecord, or None if filtered."""
    file_path: str = issue.get("filename", "")
    line_number: int = issue.get("line_number", 0)
    test_id: str = issue.get("test_id", "")
    test_name: str = issue.get("test_name", "")
    severity_str: str = issue.get("issue_severity", "LOW").upper()
    description: str = issue.get("issue_text", "No description")
    code: str = issue.get("code", "")

    # Filter test files — e.g. test_auth.py with hardcoded PASSWORD
    if is_test_file(file_path):
        _log(f"  ↳ Skipping test file: {os.path.basename(file_path)}")
        return None

    package_name = _infer_package_name(file_path, target_path)
    finding_type = _map_finding_type(test_id, test_name)
    severity = _SEVERITY_MAP.get(severity_str, "LOW")

    snippet_lines = code.splitlines()[:5]
    snippet = "\n".join(snippet_lines) if snippet_lines else None

    return FindingRecord(
        package_name=package_name,
        file_path=file_path,
        line_number=line_number,
        finding_type=finding_type,   # type: ignore[arg-type]
        severity=severity,           # type: ignore[arg-type]
        description=f"[{test_id}] {description}",
        code_snippet=snippet,
        raw_bandit_output=json.dumps(issue),
    )


# ── Bandit runner ──────────────────────────────────────────────────────────────

def run_bandit(target_path: str) -> list[dict[str, Any]]:
    """
    Execute Bandit against *target_path* and return the raw results list.

    Bandit exits 0 (no issues) or 1 (issues found) — both are valid.
    Exit code 2 means an actual error.
    """
    _log(f"Running: bandit -r {target_path} -f json -ll")

    cmd = [
        sys.executable, "-m", "bandit",
        "-r", target_path,
        "-f", "json",
        "-ll",       # LOW and above
        "--quiet",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        raise RuntimeError(
            "Bandit is not installed. Install with: pip install bandit"
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Bandit timed out scanning {target_path}")

    if result.returncode == 2:
        raise RuntimeError(
            f"Bandit exited with code 2 (error).\nstderr: {result.stderr[:500]}"
        )

    raw = result.stdout.strip()
    if not raw:
        _log("Bandit produced no output — target may be empty or all files skipped.")
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Could not parse Bandit JSON: {exc}\n"
            f"Raw (first 500): {raw[:500]}"
        )

    issues: list[dict] = data.get("results", [])
    _log(f"Bandit returned {len(issues)} raw issue(s) before filtering.")
    return issues


# ── Public API ─────────────────────────────────────────────────────────────────

def scan(target_path: str) -> list[FindingRecord]:
    """
    Full scan pipeline:  Bandit → filter test files → FindingRecord conversion.

    Parameters
    ----------
    target_path : str
        Path to scan (directory or file).

    Returns
    -------
    list[FindingRecord]
        Filtered, typed findings ready for downstream agents.
    """
    abs_target = os.path.abspath(target_path)
    if not os.path.exists(abs_target):
        _log(f"ERROR: Target path does not exist: {abs_target}")
        return []

    _log(f"Starting scan — target: '{abs_target}'")

    try:
        issues = run_bandit(abs_target)
    except RuntimeError as exc:
        _log(f"ERROR: {exc}")
        _log("Returning empty findings list (install bandit to enable full scanning).")
        return []

    findings: list[FindingRecord] = []
    skipped = 0

    for issue in issues:
        record = _bandit_to_finding(issue, abs_target)
        if record is None:
            skipped += 1
        else:
            findings.append(record)

    _log(
        f"Scan complete — {len(findings)} finding(s) retained, "
        f"{skipped} skipped (test files / filtered)."
    )

    for i, f in enumerate(findings, 1):
        _log(
            f"  [{i}] {f.severity:8s} | {f.finding_type:20s} | "
            f"{os.path.relpath(f.file_path, abs_target)}:{f.line_number}  "
            f"(pkg: {f.package_name})"
        )

    return findings


# ── LangGraph node ─────────────────────────────────────────────────────────────

def run_scanner(state: dict) -> dict:
    """
    LangGraph node — reads state["target_path"], runs scan(), writes state["findings"].
    """
    target_path: str = state.get("target_path", ".")
    _log(f"Scanner node invoked — target: {target_path}")
    findings = scan(target_path)
    _log(f"Scanner node complete — {len(findings)} finding(s) emitted.")
    return {"findings": findings}


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "vuln_app/"
    results = scan(target)
    print(f"\nTotal: {len(results)} findings")
    for r in results:
        print(f"  {r.severity:6s} | {r.finding_type:20s} | {r.file_path}:{r.line_number}")
