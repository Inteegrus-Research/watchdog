"""
agents/threat_correlator.py
----------------------------
WATCHDOG Threat Correlator Agent — Day 3 full implementation.

Pipeline role:
  - For each unique package in state["fingerprints"], build a rich query
    string from its capability signals and trust score, then perform a
    semantic similarity search against the ChromaDB attack-pattern knowledge
    base (seeded by data/seed_chromadb.py on Day 1).
  - Determine risk level from similarity + trust score adjustments.
  - Emit a ThreatAssessment per package.
  - Flag borderline results for deeper analysis (Day 4 challenge loop).

Risk-level decision logic:
  Base (from ChromaDB cosine similarity):
    similarity >= 0.80  → CRITICAL
    similarity >= 0.55  → HIGH
    similarity >= 0.35  → MEDIUM
    otherwise           → LOW

  Trust-score adjustment (applied AFTER base):
    trust_score < 0.30  → bump one level up (MEDIUM→HIGH, HIGH→CRITICAL, etc.)
    trust_score > 0.85  → reduce one level (CRITICAL→HIGH, HIGH→MEDIUM, etc.)

  ⚠️ EXTRA RULE for demo clarity:
      If trust_score < 0.1 AND any of (network, base64, subprocess) capabilities
      are present, the risk is forced to CRITICAL — this ensures that
      extremely suspicious packages (like our simulated `computil`) get the
      highest severity without hardcoding package names.

  Requires-deeper-analysis flag:
    Set True when base level is HIGH or CRITICAL but similarity < 0.80
    (i.e. the pattern match is suggestive but not conclusive).

ChromaDB note:
  ChromaDB with L2 distance returns *distance* values (lower = more similar).
  With cosine distance (the default for sentence-transformers) it returns
  1 - cosine_similarity, so similarity = 1 - distance.
  If the collection was seeded without specifying distance, we assume cosine.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime
from typing import Literal

_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_AGENT_DIR, ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from schemas.models import (
    CapabilityFingerprint,
    ThreatAssessment,
    TrustSignal,
)

# ── Logging ────────────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[threat_correlator {ts}] {msg}")


# ── Risk level helpers ─────────────────────────────────────────────────────────

_RISK_ORDER = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _bump_up(level: str) -> str:
    idx = _RISK_ORDER.index(level)
    return _RISK_ORDER[min(idx + 1, len(_RISK_ORDER) - 1)]


def _bump_down(level: str) -> str:
    idx = _RISK_ORDER.index(level)
    return _RISK_ORDER[max(idx - 1, 0)]


def _similarity_to_risk(similarity: float) -> str:
    """Map a ChromaDB similarity score (0–1) to a base risk level."""
    if similarity >= 0.80:
        return "CRITICAL"
    if similarity >= 0.55:
        return "HIGH"
    if similarity >= 0.35:
        return "MEDIUM"
    return "LOW"


def _adjust_for_trust(risk: str, trust_score: float) -> str:
    """Bump risk up for low‑trust maintainers, down for highly trusted ones."""
    if trust_score < 0.30:
        adjusted = _bump_up(risk)
        if adjusted != risk:
            _log(f"    Trust adjustment: {risk} → {adjusted} (trust={trust_score:.2f} < 0.30)")
        return adjusted
    if trust_score > 0.85:
        adjusted = _bump_down(risk)
        if adjusted != risk:
            _log(f"    Trust adjustment: {risk} → {adjusted} (trust={trust_score:.2f} > 0.85)")
        return adjusted
    return risk


# ── Query string builder ───────────────────────────────────────────────────────

def _build_query(fp: CapabilityFingerprint, trust: TrustSignal) -> str:
    """
    Build a human‑readable query string from a CapabilityFingerprint + TrustSignal.
    This is what gets embedded and compared against the attack‑pattern vectors.
    """
    parts: list[str] = []

    if fp.network_calls:
        parts.append("network socket connections")
    if fp.subprocess_calls:
        parts.append("subprocess shell execution")
    if fp.base64_encoded_payloads:
        parts.append("base64 encoded payload decode at install time")
    if fp.env_variable_access:
        parts.append("environment variable access os.environ")
    if fp.filesystem_writes:
        parts.append("filesystem writes outside package directory")
    if fp.install_hook_modified:
        parts.append("modified install hook setup.py")
    if trust.account_age_days is not None and trust.account_age_days < 90:
        parts.append(f"new maintainer account only {trust.account_age_days} days old")
    if trust.anomalies:
        parts.append("maintainer anomalies: " + "; ".join(trust.anomalies[:3]))

    # Append raw fingerprint text for richer embedding
    parts.append(fp.fingerprint_text)

    return " | ".join(parts)


# ── ChromaDB query (with graceful fallback) ────────────────────────────────────

def _query_chromadb(query_text: str, n_results: int = 2) -> list[dict]:
    """
    Query the ChromaDB attack_patterns collection.

    Returns a list of result dicts with keys:
      id, attack_name, year, distance, similarity

    If ChromaDB is not seeded or unavailable, returns an empty list.
    """
    try:
        from utils.chroma_utils import get_chroma_collection
        collection = get_chroma_collection()

        if collection.count() == 0:
            _log("  WARN: ChromaDB collection is empty — run data/seed_chromadb.py first.")
            return []

        raw = collection.query(
            query_texts=[query_text],
            n_results=min(n_results, collection.count()),
            include=["metadatas", "distances"],
        )

        results: list[dict] = []
        for i in range(len(raw["ids"][0])):
            dist: float = raw["distances"][0][i]
            # ChromaDB with cosine distance: similarity = 1 - distance
            similarity = max(0.0, min(1.0, 1.0 - dist))
            meta = raw["metadatas"][0][i]
            results.append({
                "id":           raw["ids"][0][i],
                "attack_name":  meta.get("attack_name", "Unknown"),
                "year":         meta.get("year", 0),
                "distance":     dist,
                "similarity":   similarity,
            })
        return results

    except ImportError:
        _log("  WARN: chromadb not installed — using heuristic-only risk assessment.")
        return []
    except Exception as exc:  # noqa: BLE001
        _log(f"  WARN: ChromaDB query failed: {exc} — using heuristic-only risk.")
        return []


# ── Heuristic fallback (no ChromaDB) ─────────────────────────────────────────

def _heuristic_risk(fp: CapabilityFingerprint, trust: TrustSignal) -> tuple[str, float, str]:
    """
    Rule‑based risk estimate when ChromaDB is unavailable.
    Returns (risk_level, synthetic_similarity, closest_pattern_name).
    """
    # Count how many XZ‑Utils‑like signals are present
    signals = sum([
        fp.network_calls,
        fp.base64_encoded_payloads,
        fp.subprocess_calls,
        fp.env_variable_access,
        fp.install_hook_modified,
    ])

    if signals >= 3:
        return "HIGH", 0.65, "XZ Utils Supply Chain Compromise (heuristic)"
    if signals >= 2:
        return "MEDIUM", 0.45, "PyTorch-nightly Dependency Confusion (heuristic)"
    if signals >= 1:
        return "LOW", 0.25, "Generic suspicious capability (heuristic)"
    return "NONE", 0.05, "No suspicious capabilities detected"


# ── Per‑package assessment ─────────────────────────────────────────────────────

def assess_package(
    fp: CapabilityFingerprint,
    trust: TrustSignal,
) -> ThreatAssessment:
    """
    Produce a ThreatAssessment for one package by combining:
      - ChromaDB semantic similarity search (or heuristic fallback)
      - Trust score adjustment
      - Extremely low‑trust + suspicious capabilities → CRITICAL (demo‑safe rule)

    Parameters
    ----------
    fp    : CapabilityFingerprint  from Code Analyst
    trust : TrustSignal            from Trust Analyst

    Returns
    -------
    ThreatAssessment
    """
    _log(f"  Assessing package: '{fp.package_name}'")

    query_text = _build_query(fp, trust)
    _log(f"    Query ({len(query_text)} chars): {query_text[:120]}...")

    chroma_results = _query_chromadb(query_text)

    if chroma_results:
        top = chroma_results[0]
        similarity   = top["similarity"]
        attack_name  = top["attack_name"]
        attack_year  = top["year"]
        base_risk    = _similarity_to_risk(similarity)
        source       = "ChromaDB"

        _log(
            f"    ChromaDB top match: '{attack_name}' ({attack_year})  "
            f"similarity={similarity:.3f}  base_risk={base_risk}"
        )

        # Build exploit/trust summaries for the report
        exploit_summary = (
            f"Capability analysis detected: "
            + ", ".join(
                cap for cap, flag in [
                    ("network calls",      fp.network_calls),
                    ("subprocess exec",    fp.subprocess_calls),
                    ("base64 payloads",    fp.base64_encoded_payloads),
                    ("env access",         fp.env_variable_access),
                    ("filesystem writes",  fp.filesystem_writes),
                    ("install hook mod",   fp.install_hook_modified),
                ] if flag
            ) or "no suspicious capabilities"
        )

        trust_summary = (
            f"Maintainer '{trust.maintainer_username or 'unknown'}': "
            f"trust_score={trust.trust_score:.2f}, "
            f"account_age={trust.account_age_days or '?'}d, "
            f"commits={trust.commit_count or '?'}"
        )
        if trust.anomalies:
            trust_summary += f".  Anomalies: {'; '.join(trust.anomalies[:3])}"

    else:
        # ChromaDB unavailable — fall back to heuristics
        base_risk, similarity, attack_name = _heuristic_risk(fp, trust)
        attack_year = 0
        source = "heuristic"
        exploit_summary = f"Heuristic analysis: {attack_name}"
        trust_summary = f"Trust score: {trust.trust_score:.2f}"
        _log(f"    Heuristic risk: {base_risk}  similarity(approx)={similarity:.2f}")

    # Apply trust‑score adjustment
    final_risk = _adjust_for_trust(base_risk, trust.trust_score)

    # ── EXTRA RULE: extremely low trust + suspicious capabilities → CRITICAL ──
    if trust.trust_score < 0.1 and (fp.network_calls or fp.base64_encoded_payloads or fp.subprocess_calls):
        if final_risk != "CRITICAL":
            _log(f"    Extremely low trust + suspicious capabilities → forcing CRITICAL")
            final_risk = "CRITICAL"
    # ───────────────────────────────────────────────────────────────────────────

    # Requires‑deeper‑analysis flag: borderline HIGH/CRITICAL matches
    needs_deeper = (
        final_risk in ("HIGH", "CRITICAL")
        and similarity < 0.80
    )
    if needs_deeper:
        _log(f"    Flagging for deeper analysis (similarity={similarity:.3f} < 0.80 threshold)")

    reasoning = (
        f"[{source}] Closest attack: '{attack_name}' | "
        f"similarity={similarity:.3f} → base_risk={base_risk} | "
        f"trust_score={trust.trust_score:.2f} → final_risk={final_risk}. "
        + (f"Flagged for deeper analysis." if needs_deeper else "")
    )

    risk_emoji = {"NONE":"✅","LOW":"🟢","MEDIUM":"🟡","HIGH":"🟠","CRITICAL":"🔴"}.get(final_risk,"❓")
    _log(f"    {risk_emoji}  final_risk={final_risk}  deeper={needs_deeper}")

    return ThreatAssessment(
        package_name=fp.package_name,
        risk_level=final_risk,                                  # type: ignore[arg-type]
        closest_attack_pattern=attack_name if chroma_results else None,
        pattern_similarity_score=round(similarity, 4),
        exploit_assessment_summary=exploit_summary,
        trust_signal_summary=trust_summary,
        final_reasoning=reasoning,
        requires_deeper_analysis=needs_deeper,
    )


# ── Public API ─────────────────────────────────────────────────────────────────

def correlate(
    fingerprints: list[CapabilityFingerprint],
    trust_signals: list[TrustSignal],
) -> list[ThreatAssessment]:
    """
    Run threat correlation for all packages.

    Parameters
    ----------
    fingerprints  : from Code Analyst Agent
    trust_signals : from Trust Analyst Agent

    Returns
    -------
    list[ThreatAssessment]
        One assessment per package in fingerprints.
    """
    if not fingerprints:
        _log("No fingerprints to correlate.")
        return []

    # Build lookup: package_name → TrustSignal
    trust_lookup: dict[str, TrustSignal] = {
        ts.package_name: ts for ts in trust_signals
    }

    _log(
        f"Correlating {len(fingerprints)} fingerprint(s) against "
        f"attack‑pattern knowledge base..."
    )

    assessments: list[ThreatAssessment] = []
    for fp in fingerprints:
        trust = trust_lookup.get(
            fp.package_name,
            TrustSignal(
                package_name=fp.package_name,
                trust_score=0.5,
                reasoning="No trust signal available — neutral score assumed.",
            ),
        )
        assessment = assess_package(fp, trust)
        assessments.append(assessment)

    _log(f"Threat Correlator complete — {len(assessments)} assessment(s) produced.")
    for a in assessments:
        _log(f"  {a.package_name:<20s}  risk={a.risk_level:<8s}  "
             f"sim={a.pattern_similarity_score:.3f}  deeper={a.requires_deeper_analysis}")

    return assessments


# ── LangGraph node ─────────────────────────────────────────────────────────────

def run_threat_correlator(state: dict) -> dict:
    """
    LangGraph node — reads state["fingerprints"] + state["trust_signals"],
    writes state["threat_assessments"].
    """
    fingerprints  = state.get("fingerprints",  [])
    trust_signals = state.get("trust_signals", [])

    _log(
        f"Threat Correlator node invoked — "
        f"{len(fingerprints)} fingerprint(s), {len(trust_signals)} trust signal(s)."
    )

    assessments = correlate(fingerprints, trust_signals)
    return {"threat_assessments": assessments}


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json as _json
    from agents.scanner import scan
    from agents.code_analyst import analyse_findings
    from agents.trust_analyst import analyse_trust

    target = sys.argv[1] if len(sys.argv) > 1 else "vuln_app/"
    findings      = scan(target)
    fingerprints  = analyse_findings(findings)
    trust_signals = analyse_trust(findings, use_llm=False)
    assessments   = correlate(fingerprints, trust_signals)

    print(f"\nThreat Assessments ({len(assessments)}):")
    for a in assessments:
        print(f"  {a.package_name:<20s}  {a.risk_level:<8s}  "
              f"sim={a.pattern_similarity_score}  "
              f"pattern='{a.closest_attack_pattern}'")