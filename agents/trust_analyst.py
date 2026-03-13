"""
agents/trust_analyst.py
------------------------
WATCHDOG Trust Analyst Agent — Day 2 full implementation.

Pipeline role:
  - For each unique package found in state["findings"], loads its maintainer
    metadata from data/metadata/maintainer_fake.json.
  - Computes a rule-based trust score (always works, no LLM required).
  - Optionally enriches the verdict with an Ollama LLM explanation
    (uses Mistral-7B if available; gracefully falls back if Ollama is offline).
  - Returns List[TrustSignal] — one per unique package.

Trust score formula (rule-based):
  Start at 1.0 (fully trusted).
  Penalties:
    - account_age_days < 30   → -0.50 (very new account)
    - account_age_days < 90   → -0.25
    - commits < 5             → -0.25 (barely any history)
    - commits < 20            → -0.10
    - pgp_key_listed == false → -0.10
    - previous maintainer removed in past 90 days → -0.15
    - release_key_in_project_keys_file == false → -0.10
  Clamp to [0.0, 1.0].
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from typing import Any

_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_AGENT_DIR, ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from schemas.models import FindingRecord, TrustSignal

# ── Logging ────────────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[trust_analyst {ts}] {msg}")


# ── Default metadata path ──────────────────────────────────────────────────────

_DEFAULT_METADATA_PATH = os.path.join(
    _PROJECT_ROOT, "data", "metadata", "maintainer_fake.json"
)

# ── Metadata loader ────────────────────────────────────────────────────────────

def _load_metadata(metadata_path: str) -> dict[str, Any]:
    """Load and return the maintainer metadata JSON."""
    if not os.path.isfile(metadata_path):
        _log(f"WARN: Metadata file not found: {metadata_path}")
        return {}
    with open(metadata_path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# ── Package name resolver ──────────────────────────────────────────────────────

def _resolve_package(package_name: str, metadata: dict[str, Any]) -> str:
    """
    Map a raw package_name (from the file path) to a key in the metadata dict.

    Strategy:
      1. Direct match (e.g. 'computil' → 'computil').
      2. Case-insensitive match.
      3. Partial match (metadata key is substring of package_name or vice versa).
      4. Fallback to a generic 'unknown' sentinel.
    """
    if package_name in metadata:
        return package_name
    lower = package_name.lower()
    for key in metadata:
        if key.lower() == lower:
            return key
    for key in metadata:
        k = key.lower()
        if k in lower or lower in k:
            return key
    return "__unknown__"


# ── Rule-based trust scorer ────────────────────────────────────────────────────

def _rule_based_trust(
    pkg_meta: dict[str, Any],
) -> tuple[float, list[str], str]:
    """
    Compute a deterministic trust score from metadata fields.

    Returns
    -------
    (trust_score, anomalies, reasoning)
    """
    score = 1.0
    anomalies: list[str] = []
    reasons: list[str] = []

    maintainer = pkg_meta.get("current_maintainer", {})
    pkg_info = pkg_meta.get("package_metadata", {})

    age_days: int = maintainer.get("account_age_days", 9999)
    commits: int = maintainer.get("commits_to_this_repo", 999)
    pgp: bool = maintainer.get("pgp_key_listed", True)
    key_in_file: bool = pkg_info.get("release_key_in_project_keys_file", True)
    prev_maintainers: list[dict] = pkg_meta.get("previous_maintainers", [])

    # ── Account age penalties ──────────────────────────────────────────────────
    if age_days < 30:
        score -= 0.50
        anomalies.append(f"Account created only {age_days} days ago — extremely new")
        reasons.append(f"Account age ({age_days}d) is critically short (-0.50)")
    elif age_days < 90:
        score -= 0.25
        anomalies.append(f"Account is only {age_days} days old — below 90-day threshold")
        reasons.append(f"Account age ({age_days}d) is below safe threshold (-0.25)")

    # ── Commit count penalties ─────────────────────────────────────────────────
    if commits < 5:
        score -= 0.25
        anomalies.append(f"Only {commits} commit(s) to this repository — almost no history")
        reasons.append(f"Commit count ({commits}) is critically low (-0.25)")
    elif commits < 20:
        score -= 0.10
        anomalies.append(f"Low commit count ({commits}) compared to prior maintainers")
        reasons.append(f"Low commit history (-0.10)")

    # ── PGP key ────────────────────────────────────────────────────────────────
    if not pgp:
        score -= 0.10
        anomalies.append("No PGP key listed for this maintainer account")
        reasons.append("Missing PGP key (-0.10)")

    # ── Release signing key ────────────────────────────────────────────────────
    if not key_in_file:
        score -= 0.10
        anomalies.append("Release tag not signed with a key in the project's KEYS file")
        reasons.append("Release key not in KEYS file (-0.10)")

    # ── Previous maintainer removal ────────────────────────────────────────────
    if prev_maintainers:
        removed = [
            m for m in prev_maintainers
            if m.get("commits_to_this_repo", 0) > 50
        ]
        if removed:
            score -= 0.15
            names = ", ".join(m.get("username", "?") for m in removed[:3])
            anomalies.append(
                f"Long-standing maintainer(s) removed: {names}"
            )
            reasons.append("Removal of experienced maintainer (-0.15)")

    score = max(0.0, min(1.0, score))

    # ── Known-good override ────────────────────────────────────────────────────
    known_good = pkg_meta.get("trust_score")
    if known_good is not None and not anomalies:
        # If the metadata already has a pre-computed score AND no anomalies,
        # use it (covers the benign packages: requests, numpy, flask).
        score = float(known_good)

    reasoning = (
        f"Rule-based trust computation: started at 1.0. "
        + ("; ".join(reasons) if reasons else "No penalties applied.")
        + f" Final score: {score:.2f}."
    )

    return score, anomalies, reasoning


# ── LLM enrichment (optional) ─────────────────────────────────────────────────

_LLM_SYSTEM_PROMPT = """\
You are a cybersecurity analyst specialising in software supply chain security.
Given metadata about a package maintainer, you must assess their trustworthiness
and identify any suspicious patterns.

Respond ONLY with a valid JSON object — no preamble, no markdown fences.
Format:
{
  "provenance_score": <integer 0-100>,
  "explanation": "<one concise paragraph>",
  "anomalies": ["<anomaly 1>", "<anomaly 2>"]
}

Rules:
- provenance_score 0-20  = CRITICAL risk (almost certainly malicious)
- provenance_score 21-40 = HIGH risk
- provenance_score 41-60 = MEDIUM risk
- provenance_score 61-80 = LOW risk
- provenance_score 81-100 = trusted
"""

_LLM_USER_TEMPLATE = """\
Package: {package_name}
Current maintainer: {maintainer_name}
Account age: {account_age_days} days
Commits to this repo: {commits}
PGP key listed: {pgp}
Previous maintainers had up to {prev_years} years of history.
Release key in KEYS file: {key_in_file}
Pre-computed anomalies: {anomalies}

Assess this maintainer's trustworthiness.
"""


def _llm_enrich(
    package_name: str,
    pkg_meta: dict[str, Any],
    rule_score: float,
    rule_anomalies: list[str],
) -> tuple[float, str, list[str]]:
    """
    Call Ollama (mistral) for an LLM-enriched trust assessment.
    Returns (trust_score_0_to_1, explanation, anomalies).
    Falls back to the rule-based result on any error.
    """
    try:
        import ollama  # type: ignore
    except ImportError:
        _log("  ollama package not installed — using rule-based score only.")
        return rule_score, f"Rule-based score (Ollama not available): {rule_score:.2f}", rule_anomalies

    maintainer = pkg_meta.get("current_maintainer", {})
    pkg_info = pkg_meta.get("package_metadata", {})
    prev_maintainers = pkg_meta.get("previous_maintainers", [])
    prev_years = max(
        (m.get("years_active", 0) for m in prev_maintainers), default=0
    )

    user_msg = _LLM_USER_TEMPLATE.format(
        package_name=package_name,
        maintainer_name=maintainer.get("username", "unknown"),
        account_age_days=maintainer.get("account_age_days", "?"),
        commits=maintainer.get("commits_to_this_repo", "?"),
        pgp=maintainer.get("pgp_key_listed", "?"),
        prev_years=prev_years,
        key_in_file=pkg_info.get("release_key_in_project_keys_file", "?"),
        anomalies="; ".join(rule_anomalies) if rule_anomalies else "none",
    )

    try:
        _log(f"  Calling Ollama (mistral) for trust assessment of '{package_name}'...")
        response = ollama.chat(
            model="mistral",
            messages=[
                {"role": "system", "content": _LLM_SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            options={"temperature": 0},
        )
        raw_text: str = response["message"]["content"].strip()

        # Strip markdown fences if present
        if raw_text.startswith("```"):
            raw_text = raw_text.split("```")[1]
            if raw_text.startswith("json"):
                raw_text = raw_text[4:]
        raw_text = raw_text.strip()

        parsed = json.loads(raw_text)
        llm_score = max(0, min(100, int(parsed.get("provenance_score", 50))))
        explanation: str = parsed.get("explanation", "")
        llm_anomalies: list[str] = parsed.get("anomalies", [])

        trust_score_normalized = llm_score / 100.0
        _log(
            f"  Ollama returned provenance_score={llm_score} "
            f"(normalized={trust_score_normalized:.2f})"
        )
        return trust_score_normalized, explanation, llm_anomalies

    except ollama.ResponseError as exc:
        _log(f"  WARN: Ollama API error: {exc}. Using rule-based score.")
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        _log(f"  WARN: Could not parse Ollama response: {exc}. Using rule-based score.")
    except Exception as exc:  # noqa: BLE001
        _log(f"  WARN: Unexpected Ollama error: {exc}. Using rule-based score.")

    return rule_score, f"Rule-based fallback (Ollama error): {rule_score:.2f}", rule_anomalies


# ── Public API ─────────────────────────────────────────────────────────────────

def assess_package_trust(
    package_name: str,
    metadata: dict[str, Any],
    use_llm: bool = True,
) -> TrustSignal:
    """
    Produce a TrustSignal for *package_name* using its entry in *metadata*.

    Parameters
    ----------
    package_name : str
        Package name as inferred from the file path.
    metadata : dict
        Full maintainer_fake.json loaded as a Python dict.
    use_llm : bool
        If True, attempt to enrich with Ollama (falls back to rule-based).

    Returns
    -------
    TrustSignal
    """
    resolved_key = _resolve_package(package_name, metadata)

    if resolved_key == "__unknown__":
        _log(f"  Package '{package_name}' not in metadata — assigning neutral signal.")
        return TrustSignal(
            package_name=package_name,
            maintainer_username=None,
            account_age_days=None,
            commit_count=None,
            previous_maintainers=[],
            trust_score=0.5,
            anomalies=["Package not found in known maintainer metadata"],
            reasoning="No maintainer metadata available; neutral trust score assigned.",
        )

    pkg_meta = metadata[resolved_key]
    maintainer = pkg_meta.get("current_maintainer", {})
    prev_maintainers = pkg_meta.get("previous_maintainers", [])

    _log(f"  Assessing: '{package_name}' (metadata key: '{resolved_key}')")

    # ── Rule-based baseline ────────────────────────────────────────────────────
    rule_score, rule_anomalies, rule_reasoning = _rule_based_trust(pkg_meta)

    # ── Optional LLM enrichment ────────────────────────────────────────────────
    if use_llm:
        final_score, reasoning, anomalies = _llm_enrich(
            package_name, pkg_meta, rule_score, rule_anomalies
        )
    else:
        final_score, reasoning, anomalies = rule_score, rule_reasoning, rule_anomalies

    # If LLM gave empty anomalies but rules found some, keep rule anomalies
    if not anomalies and rule_anomalies:
        anomalies = rule_anomalies

    known_anomalies: list[str] = pkg_meta.get("anomalies", [])
    all_anomalies = list({*anomalies, *known_anomalies})

    signal = TrustSignal(
        package_name=package_name,
        maintainer_username=maintainer.get("username"),
        account_age_days=maintainer.get("account_age_days"),
        commit_count=maintainer.get("commits_to_this_repo"),
        previous_maintainers=[m.get("username", "?") for m in prev_maintainers],
        trust_score=final_score,
        anomalies=all_anomalies,
        reasoning=reasoning,
    )

    risk_label = (
        "CRITICAL" if final_score < 0.20 else
        "HIGH"     if final_score < 0.40 else
        "MEDIUM"   if final_score < 0.60 else
        "LOW"      if final_score < 0.80 else
        "TRUSTED"
    )
    _log(
        f"  Trust result: score={final_score:.2f}  risk={risk_label}  "
        f"anomalies={len(all_anomalies)}"
    )

    return signal


def analyse_trust(
    findings: list[FindingRecord],
    metadata_path: str = _DEFAULT_METADATA_PATH,
    use_llm: bool = True,
) -> list[TrustSignal]:
    """
    Produce a TrustSignal for every unique package in *findings*.

    Parameters
    ----------
    findings : list[FindingRecord]
        From the Scanner Agent.
    metadata_path : str
        Path to maintainer_fake.json.
    use_llm : bool
        Whether to attempt Ollama enrichment.

    Returns
    -------
    list[TrustSignal]
        One signal per unique package_name.
    """
    if not findings:
        _log("No findings — nothing to assess.")
        return []

    metadata = _load_metadata(metadata_path)
    if not metadata:
        _log("WARN: Empty or missing metadata — all packages will get neutral scores.")

    _log(f"Assessing trust for {len(findings)} finding(s)...")

    seen_packages: set[str] = set()
    signals: list[TrustSignal] = []

    for finding in findings:
        pkg = finding.package_name
        if pkg in seen_packages:
            continue
        seen_packages.add(pkg)
        signal = assess_package_trust(pkg, metadata, use_llm=use_llm)
        signals.append(signal)

    _log(f"Trust Analyst complete — {len(signals)} signal(s) produced.")
    return signals


# ── LangGraph node ─────────────────────────────────────────────────────────────

def run_trust_analyst(state: dict) -> dict:
    """
    LangGraph node — reads state["findings"], writes state["trust_signals"].
    Respects state["use_llm"] flag (defaults True) for easy testing without Ollama.
    """
    findings: list[FindingRecord] = state.get("findings", [])
    use_llm: bool = state.get("use_llm", True)

    _log(f"Trust Analyst node invoked — {len(findings)} finding(s), use_llm={use_llm}.")
    signals = analyse_trust(findings, use_llm=use_llm)
    _log(f"Trust Analyst node complete — {len(signals)} signal(s) emitted.")
    return {"trust_signals": signals}


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from agents.scanner import scan
    target = sys.argv[1] if len(sys.argv) > 1 else "vuln_app/"
    findings = scan(target)
    signals = analyse_trust(findings, use_llm=False)
    print(f"\nTrust Signals ({len(signals)}):")
    for s in signals:
        print(f"  {s.package_name:<20s} score={s.trust_score:.2f}  "
              f"anomalies={len(s.anomalies)}")
        if s.anomalies:
            for a in s.anomalies[:3]:
                print(f"    • {a}")
