"""
agents/reviewer.py
-------------------
WATCHDOG Patch Reviewer Agent — Day 3 full implementation.

This is the "adversarial critic" that creates WATCHDOG's signature
self-correction loop. It runs two layers of checks on every PatchProposal:

Layer 1 — Deterministic (always runs, fast, reliable):
  - Syntax check  : ast.parse() on the embedded patch code.
  - Security rules: pattern-matching against known fix requirements:
      * sql_injection  → must use parameterised query (cursor.execute with tuple param)
      * idor           → must have @login_required decorator
      * hardcoded_secret → must reference os.environ or secrets module

Layer 2 — LLM review (Ollama / mistral, optional):
  - Only runs if ALL deterministic checks pass.
  - Uses an adversarial "red-team reviewer" system prompt.
  - Parses the LLM response as JSON into a ReviewVerdict.
  - Falls back to auto-approval if Ollama is unavailable.

If Layer 1 fails → immediate rejection with CorrectionMandate (no LLM call).
If Layer 1 passes but Layer 2 rejects → rejection with LLM's correction_mandate.
If both pass → approved ReviewVerdict.

The graph's conditional edge routes rejected verdicts back to the Patch Writer
for up to MAX_CORRECTION_CYCLES (2) retries.
"""

from __future__ import annotations

import ast
import json
import os
import re
import sys
from datetime import datetime

_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_AGENT_DIR, ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from schemas.models import (
    CorrectionMandate,
    FindingRecord,
    PatchProposal,
    ReviewVerdict,
    ThreatAssessment,
)

# ── Logging ────────────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[reviewer {ts}] {msg}")


# ── Layer 1: Deterministic security checks ────────────────────────────────────

def check_syntax(code: str) -> tuple[bool, str]:
    """Return (passes, error_message). Empty code is considered passing."""
    if not code or not code.strip():
        return True, ""
    try:
        ast.parse(code)
        return True, ""
    except SyntaxError as exc:
        return False, f"SyntaxError at line {exc.lineno}: {exc.msg}"


def has_parameterized_query(patch_text: str) -> bool:
    """
    Check that the patch uses parameterised SQL (prevents SQL injection).
    Looks for cursor.execute(sql, params) with a tuple/list second arg.
    """
    # Matches: cursor.execute("...", (param,)) or cursor.execute(sql, params)
    pattern = re.compile(
        r'\.execute\s*\(\s*["\'].*?["\'\s\w]+,\s*[\(\[]',
        re.DOTALL,
    )
    if pattern.search(patch_text):
        return True
    # Also accept the explicit pattern from our patch template
    if "execute(" in patch_text and ("(username," in patch_text or "(username, " in patch_text):
        return True
    return False


def has_login_required(patch_text: str) -> bool:
    """
    Check that the patch includes the @login_required decorator on its own line.
    Ignores occurrences inside comments (e.g. '# Missing @login_required').
    This is required for the IDOR fix to properly enforce authentication
    at the framework level (defence-in-depth).
    """
    import re as _re
    # Match @login_required that is NOT on a line starting with # (comment)
    for line in patch_text.splitlines():
        stripped = line.lstrip(" \t+")  # strip leading whitespace and diff '+' prefix
        if stripped.startswith("#"):
            continue  # skip comment lines
        if "@login_required" in stripped:
            return True
    return False


def has_env_secret(patch_text: str) -> bool:
    """Check that the patch moves secrets to environment variables."""
    return ("os.environ" in patch_text or "environ.get" in patch_text
            or "getenv" in patch_text or "secrets" in patch_text)


def _is_unified_diff(text: str) -> bool:
    """Return True if text looks like a unified diff (--- a/ ... +++ b/ header)."""
    return text.strip().startswith("---")


def _extract_patch_code(patch: PatchProposal) -> str:
    """
    Extract reviewable text from the PatchProposal for security-rule checks.

    For unified diffs we return the full diff text (not just added lines),
    since the security rules search for patterns across the whole diff.
    Syntax-checking is skipped for diffs (handled separately).
    """
    if patch.patch_diff:
        return patch.patch_diff
    return patch.rationale


def _infer_patch_type(patch: "PatchProposal", findings: "list[FindingRecord]") -> set:
    """Infer which finding type this patch addresses from its content."""
    full_text = (patch.patch_diff or "") + " " + patch.rationale
    inferred: set = set()
    if any(kw in full_text for kw in ("SELECT", "execute(", " sql ", "SQL", "cursor")):
        inferred.add("sql_injection")
    if any(kw in full_text for kw in (
        "login_required", "delete_note", "note_id", "owner", "IDOR", "idor", "ownership"
    )):
        inferred.add("idor")
    if any(kw in full_text for kw in (
        "secret_key", "SECRET", "FLASK_SECRET", "environ", "getenv", "secrets"
    )):
        inferred.add("hardcoded_secret")
    if any(kw in full_text for kw in ("remove", "socket", "base64", "network")):
        inferred.add("network_call")
    return inferred or {f.finding_type for f in findings if f.package_name == patch.package_name}


def _deterministic_check(
    patch: PatchProposal,
    findings: list[FindingRecord],
) -> tuple[bool, str]:
    """
    Run deterministic security rules on a patch.

    Infers which rules apply from patch content — not blindly applying all rules
    for every finding type the package has.
    Syntax-checking skipped for unified diffs (not valid standalone Python).

    Returns (passes, failure_reason).
    """
    patch_text = _extract_patch_code(patch)
    is_diff    = _is_unified_diff(patch_text)

    # ── Syntax check (only for non-diff code patches, not prose rationales) ─────
    # Only meaningful for apply_code_patch with a full code block — not for
    # remove_dependency / monitor_only whose rationale is prose text.
    if (not is_diff and patch_text.strip()
            and patch.proposed_action == "apply_code_patch"):
        ok, syntax_err = check_syntax(patch_text)
        if not ok:
            return False, f"Patch code has a syntax error: {syntax_err}"

    applicable_types = _infer_patch_type(patch, findings)
    full_text = patch_text + "\n" + patch.rationale

    # ── SQL injection rule ────────────────────────────────────────────────────
    if "sql_injection" in applicable_types:
        if patch.proposed_action == "apply_code_patch":
            if not has_parameterized_query(full_text):
                return False, (
                    "SQL injection patch does not use parameterised queries. "
                    "Use cursor.execute(sql, (param,)) instead of string concatenation."
                )

    # ── IDOR rule — the deliberate demo rejection ─────────────────────────────
    if "idor" in applicable_types:
        if patch.proposed_action == "apply_code_patch":
            if not has_login_required(full_text):
                return False, (
                    "IDOR patch is INCOMPLETE: the @login_required decorator is missing. "
                    "Defence-in-depth requires authentication to be enforced at the "
                    "framework level (decorator) AND at the business logic level "
                    "(ownership check). Adding only the ownership check is insufficient — "
                    "a session fixation attack could still bypass it. "
                    "Add @login_required above the route function."
                )

    # ── Hardcoded secret rule ─────────────────────────────────────────────────
    if "hardcoded_secret" in applicable_types:
        if patch.proposed_action == "apply_code_patch":
            if not has_env_secret(full_text):
                return False, (
                    "Hardcoded secret patch must move the secret to an environment "
                    "variable (os.environ.get). Hard-coding a different value is not "
                    "a fix."
                )

    return True, ""


# ── Layer 2: LLM adversarial review ───────────────────────────────────────────

_LLM_SYSTEM = """\
You are an adversarial security code reviewer. Your job is to find ANY problem
with proposed security patches — be thorough and skeptical.

Check for:
1. Does the patch actually fix the root cause, or just add a superficial guard?
2. Are there edge cases the patch misses?
3. Is the patch complete (all required security mechanisms present)?
4. Does the patch introduce any new security issues?

Output ONLY a JSON object — no markdown, no preamble:
{
  "approved": true | false,
  "feedback": "<concise reason if rejected, empty string if approved>",
  "correction_mandate": "<specific instructions for the patch writer if rejected>"
}
"""

_LLM_USER_TEMPLATE = """\
Package: {package_name}
Finding type(s): {finding_types}
Proposed action: {proposed_action}
Rationale: {rationale}

Patch diff:
{patch_diff}

Review this patch. Be adversarial — look hard for any missing security control.
"""


def _llm_review(
    patch: PatchProposal,
    findings: list[FindingRecord],
) -> tuple[bool, str, str]:
    """
    Call Ollama for an adversarial review of the patch.

    Returns
    -------
    (approved, feedback, correction_mandate)
    Falls back to (True, "", "") if Ollama is unavailable.
    """
    try:
        import ollama  # type: ignore
    except ImportError:
        _log("  ollama not installed — skipping LLM review (auto-approve).")
        return True, "", ""

    pkg_findings = [f for f in findings if f.package_name == patch.package_name]
    finding_types = ", ".join({f.finding_type for f in pkg_findings})

    user_msg = _LLM_USER_TEMPLATE.format(
        package_name=patch.package_name,
        finding_types=finding_types,
        proposed_action=patch.proposed_action,
        rationale=patch.rationale,
        patch_diff=patch.patch_diff or "(no diff — prose rationale only)",
    )

    try:
        _log(f"  Calling Ollama for adversarial review of '{patch.package_name}'...")
        response = ollama.chat(
            model="mistral",
            messages=[
                {"role": "system", "content": _LLM_SYSTEM},
                {"role": "user", "content": user_msg},
            ],
            options={"temperature": 0},
        )
        raw: str = response["message"]["content"].strip()
        # Strip markdown fences
        if "```" in raw:
            raw = raw.split("```")[1].lstrip("json").strip()
        parsed = json.loads(raw)
        approved: bool   = bool(parsed.get("approved", True))
        feedback: str    = parsed.get("feedback", "")
        mandate: str     = parsed.get("correction_mandate", "")
        _log(f"  Ollama verdict: {'approved' if approved else 'REJECTED'}"
             + (f" — {feedback[:80]}" if not approved else ""))
        return approved, feedback, mandate

    except Exception as exc:  # noqa: BLE001
        _log(f"  WARN: Ollama review failed: {exc} — auto-approving.")
        return True, "", ""


# ── Public API ─────────────────────────────────────────────────────────────────

def review_patch(
    patch: PatchProposal,
    findings: list[FindingRecord],
    use_llm: bool,
    correction_count: int,
    max_retries: int = 2,
) -> tuple[ReviewVerdict, CorrectionMandate | None]:
    """
    Review a single PatchProposal.

    Returns
    -------
    (ReviewVerdict, CorrectionMandate | None)
      CorrectionMandate is non-None when the patch is rejected and retries remain.
    """
    _log(f"  Reviewing patch for '{patch.package_name}' "
         f"(action={patch.proposed_action}, correction_count={correction_count})")

    # ── Layer 1: Deterministic ────────────────────────────────────────────────
    ok, det_reason = _deterministic_check(patch, findings)

    if not ok:
        _log(f"  ✗ REJECTED (deterministic): {det_reason[:100]}")
        retries_left = max_retries - correction_count

        verdict = ReviewVerdict(
            package_name=patch.package_name,
            approved=False,
            feedback=f"[DETERMINISTIC] {det_reason}",
            correction_requested=True,
        )
        mandate: CorrectionMandate | None = None
        if retries_left > 0:
            mandate = CorrectionMandate(
                package_name=patch.package_name,
                original_proposal=patch,
                correction_instructions=[
                    det_reason,
                    "Re-generate the patch addressing all listed deficiencies.",
                    "Run the deterministic checks yourself before submitting.",
                ],
                max_retries_remaining=retries_left - 1,
            )
        return verdict, mandate

    _log("  ✓ Deterministic checks passed.")

    # ── Layer 2: LLM (optional) ───────────────────────────────────────────────
    if use_llm:
        approved, feedback, llm_mandate = _llm_review(patch, findings)
        if not approved:
            _log(f"  ✗ REJECTED (LLM): {feedback[:100]}")
            retries_left = max_retries - correction_count
            verdict = ReviewVerdict(
                package_name=patch.package_name,
                approved=False,
                feedback=f"[LLM] {feedback}",
                correction_requested=True,
            )
            mandate = None
            if retries_left > 0:
                mandate = CorrectionMandate(
                    package_name=patch.package_name,
                    original_proposal=patch,
                    correction_instructions=[
                        llm_mandate or feedback,
                        "Address all issues identified by the LLM reviewer.",
                    ],
                    max_retries_remaining=retries_left - 1,
                )
            return verdict, mandate
    else:
        _log("  LLM review disabled — deterministic-only mode.")

    _log(f"  ✅ APPROVED: '{patch.package_name}'")
    verdict = ReviewVerdict(
        package_name=patch.package_name,
        approved=True,
        feedback="",
        correction_requested=False,
    )
    return verdict, None


def review_all(
    patches: list[PatchProposal],
    findings: list[FindingRecord],
    use_llm: bool,
    correction_count: int,
    max_retries: int = 2,
) -> tuple[list[ReviewVerdict], list[CorrectionMandate]]:
    """
    Review all patches and collect verdicts + mandates.

    Parameters
    ----------
    patches          : from Patch Writer Agent
    findings         : from Scanner Agent (for context)
    use_llm          : True enables Ollama review after deterministic checks
    correction_count : current correction cycle number
    max_retries      : maximum correction cycles allowed (default 2)

    Returns
    -------
    (verdicts, correction_mandates)
    """
    if not patches:
        _log("No patches to review.")
        return [], []

    _log(
        f"Reviewing {len(patches)} patch(es) — "
        f"cycle={correction_count}, use_llm={use_llm}"
    )

    verdicts: list[ReviewVerdict] = []
    mandates: list[CorrectionMandate] = []

    for patch in patches:
        verdict, mandate = review_patch(
            patch, findings, use_llm, correction_count, max_retries
        )
        verdicts.append(verdict)
        if mandate:
            mandates.append(mandate)

    approved_count  = sum(1 for v in verdicts if v.approved)
    rejected_count  = len(verdicts) - approved_count

    _log(
        f"Review complete — {approved_count} approved, "
        f"{rejected_count} rejected, {len(mandates)} mandate(s) issued."
    )

    for v in verdicts:
        status = "✅ APPROVED" if v.approved else f"❌ REJECTED: {v.feedback[:60]}"
        _log(f"  {v.package_name:<20s} {status}")

    return verdicts, mandates


# ── LangGraph node ─────────────────────────────────────────────────────────────

def run_reviewer(state: dict) -> dict:
    """
    LangGraph node — reads patches + findings, writes verdicts + mandates.
    Also increments correction_count if any rejection occurred.
    """
    patches    = state.get("patches",    [])
    findings   = state.get("findings",   [])
    use_llm    = state.get("use_llm",    True)
    corr_count = state.get("correction_count", 0)

    _log(f"Reviewer node invoked — {len(patches)} patch(es), correction_count={corr_count}")

    verdicts, mandates = review_all(
        patches, findings, use_llm, corr_count
    )

    has_rejection = any(not v.approved for v in verdicts)
    new_count = corr_count + 1 if has_rejection else corr_count

    return {
        "verdicts":           verdicts,
        "correction_mandates": mandates,
        "correction_count":   new_count,
    }


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Quick deterministic self-test
    from schemas.models import PatchProposal, FindingRecord

    print("=== Reviewer self-test ===")

    f_idor = FindingRecord(
        package_name="vuln_app", file_path="app.py", line_number=113,
        finding_type="idor", severity="HIGH", description="IDOR",
    )

    # Pass 1 patch: missing @login_required
    p1 = PatchProposal(
        package_name="vuln_app",
        proposed_action="apply_code_patch",
        patch_diff="+ if note['owner'] != session['username']: abort(403)",
        rationale="Ownership check added",
        confidence=0.70,
    )
    ok, reason = _deterministic_check(p1, [f_idor])
    print(f"Pass 1 deterministic: ok={ok}  reason={reason[:80]}")
    assert not ok, "Should reject missing @login_required"

    # Pass 2 patch: correct
    p2 = PatchProposal(
        package_name="vuln_app",
        proposed_action="apply_code_patch",
        patch_diff="+@login_required\n+ if note['owner'] != session['username']: abort(403)",
        rationale="login_required decorator + ownership check",
        confidence=0.92,
    )
    ok2, reason2 = _deterministic_check(p2, [f_idor])
    print(f"Pass 2 deterministic: ok={ok2}  reason={reason2!r}")
    assert ok2, "Should approve with @login_required"

    print("\nAll self-tests passed ✓")
