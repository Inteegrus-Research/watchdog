"""
agents/patch_writer.py
-----------------------
WATCHDOG Patch Writer Agent — Day 3 full implementation.

Pipeline role:
  - Reads state["findings"], state["threat_assessments"], state["verdicts"],
    and state["correction_mandates"].
  - For each unique package, generates a concrete PatchProposal.
  - On the *first* pass the IDOR patch is intentionally generated WITHOUT the
    @login_required decorator — this is the demo's "rejection moment" that the
    Reviewer Agent will catch and push back on.
  - On the *second* pass (correction_count >= 1) the patch writer reads the
    CorrectionMandate and adds @login_required correctly.

Patch generation strategy (rule-based, deterministic, no LLM):
  - sql_injection    → parameterised query patch (correct; approved first pass)
  - idor             → ownership check patch (MISSING @login_required on pass 1)
  - hardcoded_secret → move secret to os.environ with fallback warning
  - network_call /
    base64_payload /
    subprocess_exec  → remove_dependency if trust_score < 0.30; else monitor_only
  - other            → monitor_only
"""

from __future__ import annotations

import os
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
    TrustSignal,
)

# ── Logging ────────────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[patch_writer {ts}] {msg}")


# ── Code patch templates ───────────────────────────────────────────────────────

# ── SQL Injection fix: parameterised query ─────────────────────────────────────
_SQLI_PATCH_DIFF = '''\
--- a/vuln_app/app.py
+++ b/vuln_app/app.py
@@ -82,7 +82,7 @@ def login():
-        query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
-        cursor = conn.execute(query)  # VULN-001
+        # PATCHED: use parameterised query to prevent SQL injection
+        cursor = conn.execute(
+            "SELECT * FROM users WHERE username=? AND password=?",
+            (username, password),
+        )
'''

_SQLI_PATCH_CODE = """\
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = _get_db()
        try:
            # PATCHED: parameterised query prevents SQL injection
            cursor = conn.execute(
                "SELECT * FROM users WHERE username=? AND password=?",
                (username, password),
            )
            user = cursor.fetchone()
        except Exception as exc:
            error = f"DB error: {exc}"
            user = None
        finally:
            conn.close()
        if user:
            session["username"] = user[0]
            return redirect(url_for("notes"))
        else:
            error = "Invalid credentials."
    return render_template_string(LOGIN_HTML, error=error)
"""

# ── IDOR fix (Pass 1 — intentionally MISSING @login_required for demo) ─────────
_IDOR_PATCH_DIFF_PASS1 = '''\
--- a/vuln_app/app.py
+++ b/vuln_app/app.py
@@ -113,6 +113,9 @@ def notes():
 @app.route("/delete_note/<int:note_id>", methods=["POST"])
 def delete_note(note_id: int):
+    # PATCHED: check session (ownership check added)
+    # NOTE: Missing @login_required decorator — Reviewer will catch this
     if "username" not in session:
         return jsonify({"error": "Unauthorised"}), 401
     for i, note in enumerate(NOTES):
         if note["id"] == note_id:
-            NOTES.pop(i)  # VULN-002: any user can delete any note
+            if note["owner"] != session["username"]:
+                return jsonify({"error": "Forbidden"}), 403
+            NOTES.pop(i)
             return jsonify({"deleted": note_id})
     return jsonify({"error": "Note not found"}), 404
'''

_IDOR_PATCH_CODE_PASS1 = """\
@app.route("/delete_note/<int:note_id>", methods=["POST"])
def delete_note(note_id: int):
    # PATCHED: ownership check added — but @login_required decorator MISSING
    if "username" not in session:
        return jsonify({"error": "Unauthorised"}), 401
    for i, note in enumerate(NOTES):
        if note["id"] == note_id:
            if note["owner"] != session["username"]:
                return jsonify({"error": "Forbidden"}), 403
            NOTES.pop(i)
            return jsonify({"deleted": note_id})
    return jsonify({"error": "Note not found"}), 404
"""

# ── IDOR fix (Pass 2 — corrected after Reviewer rejection) ────────────────────
_IDOR_PATCH_DIFF_PASS2 = '''\
--- a/vuln_app/app.py
+++ b/vuln_app/app.py
@@ -113,6 +113,8 @@ def notes():
+from functools import wraps
+
 @app.route("/delete_note/<int:note_id>", methods=["POST"])
+@login_required
 def delete_note(note_id: int):
+    # PATCHED: @login_required enforces authentication at framework level
+    # PATCHED: ownership check prevents IDOR
     for i, note in enumerate(NOTES):
         if note["id"] == note_id:
-            NOTES.pop(i)  # VULN-002: any user can delete any note
+            if note["owner"] != session["username"]:
+                return jsonify({"error": "Forbidden"}), 403
+            NOTES.pop(i)
             return jsonify({"deleted": note_id})
     return jsonify({"error": "Note not found"}), 404
'''

_IDOR_PATCH_CODE_PASS2 = """\
@app.route("/delete_note/<int:note_id>", methods=["POST"])
@login_required
def delete_note(note_id: int):
    # PATCHED: @login_required enforces authentication at the framework level
    # PATCHED: ownership check prevents IDOR — only note owner can delete
    for i, note in enumerate(NOTES):
        if note["id"] == note_id:
            if note["owner"] != session["username"]:
                return jsonify({"error": "Forbidden"}), 403
            NOTES.pop(i)
            return jsonify({"deleted": note_id})
    return jsonify({"error": "Note not found"}), 404
"""

# ── Hardcoded secret fix ────────────────────────────────────────────────────────
_SECRET_PATCH_DIFF = '''\
--- a/vuln_app/app.py
+++ b/vuln_app/app.py
@@ -24,3 +24,8 @@
-app.secret_key = "super_secret_watchdog_demo_key_1234"  # VULN-003
+import os as _os
+import secrets as _secrets
+import warnings as _warnings
+_secret = _os.environ.get("FLASK_SECRET_KEY")
+if not _secret:
+    _warnings.warn("FLASK_SECRET_KEY not set — using insecure random key", stacklevel=1)
+    _secret = _secrets.token_hex(32)
+app.secret_key = _secret
'''

_SECRET_PATCH_CODE = """\
import os as _os
import secrets as _secrets
import warnings as _warnings

_secret = _os.environ.get("FLASK_SECRET_KEY")
if not _secret:
    _warnings.warn(
        "FLASK_SECRET_KEY environment variable not set — using ephemeral random key. "
        "Sessions will not persist across restarts.",
        stacklevel=1,
    )
    _secret = _secrets.token_hex(32)
app.secret_key = _secret
"""


# ── Helpers ────────────────────────────────────────────────────────────────────

def _has_correction_mandate(
    package_name: str,
    correction_mandates: list[CorrectionMandate],
) -> CorrectionMandate | None:
    """Return the most recent CorrectionMandate for package_name, or None."""
    # Mandates are in order; take last one for this package
    matching = [m for m in correction_mandates if m.package_name == package_name]
    return matching[-1] if matching else None


def _was_rejected(package_name: str, verdicts: list[ReviewVerdict]) -> bool:
    """Return True if the most recent verdict for this package was a rejection."""
    matching = [v for v in verdicts if v.package_name == package_name]
    return bool(matching) and not matching[-1].approved


# ── Per-finding patch generators ───────────────────────────────────────────────

def _patch_sql_injection(finding: FindingRecord) -> PatchProposal:
    return PatchProposal(
        package_name=finding.package_name,
        proposed_action="apply_code_patch",
        patch_diff=_SQLI_PATCH_DIFF,
        rationale=(
            "SQL injection via string concatenation detected at "
            f"{finding.file_path}:{finding.line_number}. "
            "Replace with parameterised query using cursor.execute(sql, params) — "
            "this prevents any user-supplied input from being interpreted as SQL."
        ),
        confidence=0.95,
    )


def _patch_idor(
    finding: FindingRecord,
    correction_count: int,
    correction_mandates: list[CorrectionMandate],
) -> PatchProposal:
    """
    Pass 1 (correction_count == 0): deliberate omission of @login_required.
    Pass 2+ (correction_count >= 1): full correct patch with decorator.
    """
    mandate = _has_correction_mandate(finding.package_name, correction_mandates)
    use_corrected = correction_count >= 1 and mandate is not None

    if use_corrected:
        _log(
            f"  IDOR [{finding.package_name}] — applying corrected patch "
            f"(mandate: {mandate.correction_instructions[0][:60]}...)"
        )
        return PatchProposal(
            package_name=finding.package_name,
            proposed_action="apply_code_patch",
            patch_diff=_IDOR_PATCH_DIFF_PASS2,
            rationale=(
                "IDOR fixed: added @login_required decorator (correction from Reviewer) "
                "and ownership check (note[\"owner\"] == session[\"username\"]) before "
                "allowing deletion. Both layers of defence are now present."
            ),
            confidence=0.92,
        )
    else:
        _log(
            f"  IDOR [{finding.package_name}] — Pass 1: "
            "ownership check added, @login_required OMITTED (expected Reviewer rejection)"
        )
        return PatchProposal(
            package_name=finding.package_name,
            proposed_action="apply_code_patch",
            patch_diff=_IDOR_PATCH_DIFF_PASS1,
            rationale=(
                "IDOR fixed: added per-note ownership check "
                "(note[\"owner\"] == session[\"username\"]) before deletion. "
                "Any user can now only delete their own notes."
            ),
            confidence=0.70,
        )


def _patch_hardcoded_secret(finding: FindingRecord) -> PatchProposal:
    return PatchProposal(
        package_name=finding.package_name,
        proposed_action="apply_code_patch",
        patch_diff=_SECRET_PATCH_DIFF,
        rationale=(
            "Hardcoded secret key removed from source. "
            "Replace with FLASK_SECRET_KEY environment variable. "
            "If the env var is absent, a cryptographically random key is used "
            "per-process (sessions will not persist across restarts — this is "
            "intentional and forces operators to configure the env var in production)."
        ),
        confidence=0.90,
    )


def _patch_supply_chain(
    finding: FindingRecord,
    threat: ThreatAssessment | None,
    trust: TrustSignal | None,
) -> PatchProposal:
    """Patch for supply-chain suspicious findings (network, base64, etc.)."""
    trust_score = trust.trust_score if trust else 0.5
    risk = threat.risk_level if threat else "MEDIUM"

    if trust_score < 0.30 or risk == "CRITICAL":
        return PatchProposal(
            package_name=finding.package_name,
            proposed_action="remove_dependency",
            rationale=(
                f"Package '{finding.package_name}' shows behavioral indicators "
                f"consistent with a supply chain compromise (trust_score={trust_score:.2f}, "
                f"risk={risk}). The maintainer account was created recently and has very "
                "few commits. Immediate removal is recommended — do not use this package."
            ),
            confidence=0.88,
        )
    elif risk in ("HIGH", "MEDIUM"):
        return PatchProposal(
            package_name=finding.package_name,
            proposed_action="monitor_only",
            rationale=(
                f"Package '{finding.package_name}' has elevated risk signals "
                f"(trust_score={trust_score:.2f}, risk={risk}). "
                "Monitor for further releases; consider pinning to current version "
                "and reviewing future changelogs."
            ),
            confidence=0.65,
        )
    else:
        return PatchProposal(
            package_name=finding.package_name,
            proposed_action="monitor_only",
            rationale=f"Low-risk finding in '{finding.package_name}'. Monitoring only.",
            confidence=0.55,
        )


# ── Main public API ────────────────────────────────────────────────────────────

def write_patches(
    findings: list[FindingRecord],
    threat_assessments: list[ThreatAssessment],
    trust_signals: list[TrustSignal],
    verdicts: list[ReviewVerdict],
    correction_mandates: list[CorrectionMandate],
    correction_count: int,
) -> list[PatchProposal]:
    """
    Generate (or re-generate) a PatchProposal for every unique package.

    On re-generation (correction_count > 0), reads verdicts + correction_mandates
    to produce improved patches for previously-rejected proposals.

    Parameters
    ----------
    findings            : from Scanner Agent
    threat_assessments  : from Threat Correlator
    trust_signals       : from Trust Analyst
    verdicts            : from previous Reviewer pass (empty on first run)
    correction_mandates : from previous Reviewer pass (empty on first run)
    correction_count    : number of correction cycles already completed

    Returns
    -------
    list[PatchProposal]
    """
    if not findings:
        _log("No findings — no patches to generate.")
        return []

    cycle = f"Pass {correction_count + 1}"
    _log(f"Generating patches — {cycle}  ({len(findings)} finding(s))")

    # Build lookup tables
    threat_lookup: dict[str, ThreatAssessment] = {
        t.package_name: t for t in threat_assessments
    }
    trust_lookup: dict[str, TrustSignal] = {
        ts.package_name: ts for ts in trust_signals
    }

    # Group findings by (package, finding_type) — one patch per unique pair
    seen: dict[tuple[str, str], PatchProposal] = {}

    for finding in findings:
        key = (finding.package_name, finding.finding_type)
        if key in seen:
            continue

        ftype = finding.finding_type
        threat = threat_lookup.get(finding.package_name)
        trust  = trust_lookup.get(finding.package_name)
        rejected = _was_rejected(finding.package_name, verdicts)

        # Log re-generation context
        if rejected and correction_count > 0:
            mandate = _has_correction_mandate(finding.package_name, correction_mandates)
            instr = mandate.correction_instructions[0][:80] if mandate else "no mandate"
            _log(f"  Re-generating patch for '{finding.package_name}' "
                 f"(rejected on pass {correction_count}): {instr}...")

        # Choose patch strategy
        if ftype == "sql_injection":
            patch = _patch_sql_injection(finding)

        elif ftype == "idor":
            patch = _patch_idor(finding, correction_count, correction_mandates)

        elif ftype == "hardcoded_secret":
            patch = _patch_hardcoded_secret(finding)

        elif ftype in ("network_call", "base64_payload", "subprocess_exec",
                       "dangerous_import", "env_access", "filesystem_write",
                       "suspicious_install_hook"):
            patch = _patch_supply_chain(finding, threat, trust)

        else:
            patch = PatchProposal(
                package_name=finding.package_name,
                proposed_action="monitor_only",
                rationale=f"No automated patch available for '{ftype}'. Manual review required.",
                confidence=0.50,
            )

        seen[key] = patch
        _log(
            f"  [{finding.package_name}] {ftype:22s} → "
            f"{patch.proposed_action}  (conf={patch.confidence:.0%})"
        )

    patches = list(seen.values())
    _log(f"Patch Writer complete — {len(patches)} proposal(s) for cycle '{cycle}'.")
    return patches


# ── LangGraph node ─────────────────────────────────────────────────────────────

def run_patch_writer(state: dict) -> dict:
    """LangGraph node — writes state['patches']."""
    _log(f"Patch Writer node invoked — correction_count={state.get('correction_count', 0)}")

    patches = write_patches(
        findings=state.get("findings", []),
        threat_assessments=state.get("threat_assessments", []),
        trust_signals=state.get("trust_signals", []),
        verdicts=state.get("verdicts", []),
        correction_mandates=state.get("correction_mandates", []),
        correction_count=state.get("correction_count", 0),
    )
    return {"patches": patches}


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from agents.scanner import scan
    from agents.code_analyst import analyse_findings
    from agents.trust_analyst import analyse_trust

    target = sys.argv[1] if len(sys.argv) > 1 else "vuln_app/"
    findings = scan(target)
    fps      = analyse_findings(findings)
    signals  = analyse_trust(findings, use_llm=False)
    patches  = write_patches(findings, [], signals, [], [], correction_count=0)

    print(f"\nPatches ({len(patches)}):")
    for p in patches:
        print(f"  {p.package_name:<20s} → {p.proposed_action}  ({p.confidence:.0%})")
