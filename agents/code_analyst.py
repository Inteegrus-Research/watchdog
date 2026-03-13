"""
agents/code_analyst.py
-----------------------
WATCHDOG Code Analyst Agent — Day 2 full implementation.

Pipeline role:
  - Receives List[FindingRecord] from the Scanner Agent.
  - For each finding, runs the AST extractor on the affected file to build
    a CapabilityFingerprint capturing what the code is *doing*.
  - Returns List[CapabilityFingerprint] — one per unique (package, file) pair.
  - If extraction fails for a file, logs the error and skips (never crashes).
"""

from __future__ import annotations

import os
import sys
from datetime import datetime

_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_AGENT_DIR, ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from schemas.models import CapabilityFingerprint, FindingRecord
from utils.ast_extractor import ASTFindings, extract_capabilities

# ── Logging ────────────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[code_analyst {ts}] {msg}")


# ── Capability text builder ────────────────────────────────────────────────────

def _build_fingerprint_text(package_name: str, ast_findings: ASTFindings) -> str:
    """
    Build a free-text fingerprint description from ASTFindings.
    This text is later embedded by ChromaDB for semantic similarity search.
    """
    parts: list[str] = [f"Package '{package_name}' capability analysis:"]

    if ast_findings.imports:
        unique_imports = sorted(set(ast_findings.imports))
        parts.append(f"Imports: {', '.join(unique_imports[:15])}")

    if ast_findings.network_calls:
        calls = [c for _, c in ast_findings.network_calls[:5]]
        parts.append(f"Network operations: {'; '.join(calls)}")

    if ast_findings.subprocess_calls:
        calls = [c for _, c in ast_findings.subprocess_calls[:5]]
        parts.append(f"Subprocess/shell execution: {'; '.join(calls)}")

    if ast_findings.env_accesses:
        calls = [c for _, c in ast_findings.env_accesses[:3]]
        parts.append(f"Environment variable access: {'; '.join(calls)}")

    if ast_findings.base64_calls:
        calls = [c for _, c in ast_findings.base64_calls[:3]]
        parts.append(f"Base64 encoding/decoding: {'; '.join(calls)}")

    if ast_findings.filesystem_writes:
        calls = [c for _, c in ast_findings.filesystem_writes[:3]]
        parts.append(f"Filesystem writes: {'; '.join(calls)}")

    if not ast_findings.has_suspicious_capabilities:
        parts.append("No suspicious runtime capabilities detected by AST analysis.")

    return " | ".join(parts)


# ── Public API ─────────────────────────────────────────────────────────────────

def analyse_file(
    file_path: str,
    package_name: str,
) -> CapabilityFingerprint | None:
    """
    Run AST extraction on *file_path* and build a CapabilityFingerprint.

    Returns None on any error so the pipeline can continue gracefully.
    """
    try:
        ast_findings = extract_capabilities(file_path)
    except FileNotFoundError:
        _log(f"  WARN: File not found, skipping: {file_path}")
        return None
    except SyntaxError as exc:
        _log(f"  WARN: Syntax error in {file_path}: {exc}")
        return None
    except Exception as exc:  # noqa: BLE001
        _log(f"  WARN: AST extraction failed for {file_path}: {exc}")
        return None

    fingerprint_text = _build_fingerprint_text(package_name, ast_findings)

    fp = CapabilityFingerprint(
        package_name=package_name,
        network_calls=bool(ast_findings.network_calls),
        subprocess_calls=bool(ast_findings.subprocess_calls),
        env_variable_access=bool(ast_findings.env_accesses),
        filesystem_writes=bool(ast_findings.filesystem_writes),
        base64_encoded_payloads=bool(ast_findings.base64_calls),
        install_hook_modified="setup.py" in file_path or "install" in file_path.lower(),
        new_maintainer=False,   # set by Trust Analyst based on metadata
        fingerprint_text=fingerprint_text,
    )

    # Log a summary
    flags = []
    if fp.network_calls:          flags.append("network")
    if fp.subprocess_calls:       flags.append("subprocess")
    if fp.base64_encoded_payloads: flags.append("base64")
    if fp.env_variable_access:    flags.append("env_access")
    if fp.filesystem_writes:      flags.append("fs_write")

    status = f"[{', '.join(flags)}]" if flags else "[clean]"
    _log(f"  {package_name:<20s} {status}  ← {os.path.basename(file_path)}")

    return fp


def analyse_findings(findings: list[FindingRecord]) -> list[CapabilityFingerprint]:
    """
    Build a CapabilityFingerprint for every *unique* (package_name, file_path) pair
    across all findings.  Multiple findings in the same file share one fingerprint.

    Parameters
    ----------
    findings : list[FindingRecord]
        Output from the Scanner Agent.

    Returns
    -------
    list[CapabilityFingerprint]
        One fingerprint per unique file, de-duplicated by package+file key.
    """
    if not findings:
        _log("No findings to analyse.")
        return []

    _log(f"Analysing {len(findings)} finding(s) across unique files...")

    seen: dict[tuple[str, str], CapabilityFingerprint] = {}

    for finding in findings:
        key = (finding.package_name, finding.file_path)
        if key in seen:
            continue

        _log(f"  Extracting capabilities from: {finding.file_path}")
        fp = analyse_file(finding.file_path, finding.package_name)
        if fp is not None:
            seen[key] = fp

    fingerprints = list(seen.values())
    _log(f"Code Analyst complete — {len(fingerprints)} fingerprint(s) produced.")
    return fingerprints


# ── LangGraph node ─────────────────────────────────────────────────────────────

def run_code_analyst(state: dict) -> dict:
    """
    LangGraph node — reads state["findings"], writes state["fingerprints"].
    """
    findings: list[FindingRecord] = state.get("findings", [])
    _log(f"Code Analyst node invoked — {len(findings)} finding(s) to process.")
    fingerprints = analyse_findings(findings)
    _log(f"Code Analyst node complete — {len(fingerprints)} fingerprint(s) emitted.")
    return {"fingerprints": fingerprints}


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Quick standalone test
    from agents.scanner import scan
    target = sys.argv[1] if len(sys.argv) > 1 else "vuln_app/"
    findings = scan(target)
    fps = analyse_findings(findings)
    print(f"\nFingerprints ({len(fps)}):")
    for fp in fps:
        print(f"  {fp.package_name}: {fp.fingerprint_text[:120]}...")
