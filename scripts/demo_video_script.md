# 🐕 WATCHDOG — 3-Minute Demo Video Script

**Duration:** 3:00 minutes  
**Format:** Screen recording with voiceover  
**Backup:** If live demo fails, cut to pre-recorded video at 1:45

---

## Pre-Recording Checklist

- [ ] `python data/seed_chromadb.py` has been run (ChromaDB seeded)
- [ ] Terminal font size set to 20pt for readability
- [ ] Browser zoomed to 110%, dark theme active
- [ ] `vuln_app/` directory present with `computil/` backdoor
- [ ] `watchdog_report.html` from a previous run open in background tab
- [ ] Ollama running: `ollama serve` (if using `--llm`)

---

## Script

### [0:00–0:18] HOOK — The Problem

*[Screen: XZ Utils CVE description from NVD, or just a dark terminal]*

> "In March 2024, a backdoor was hidden inside XZ Utils — a compression library
> used by almost every Linux distribution. It bypassed SSH authentication entirely.
> The attacker spent **two years** building trust before inserting the payload.
>
> Snyk didn't catch it. Dependabot didn't catch it. No CVE scanner caught it —
> because there was no CVE yet.
>
> We built WATCHDOG to close that gap."

---

### [0:18–0:40] WATCHDOG OVERVIEW

*[Screen: README architecture diagram or a clean slide]*

> "WATCHDOG is a seven-agent AI system that asks one question:
> **Does this package *behave* like a supply chain attack?**
>
> Not 'does it match a known CVE' — but 'does it open a socket, decode a base64
> payload at import time, and was its maintainer account created three weeks ago?'
>
> It runs Bandit static analysis, builds a capability fingerprint, scores maintainer
> provenance, runs a ChromaDB semantic similarity search against historical attacks,
> generates patches — and then an adversarial Reviewer Agent checks every patch
> and rejects anything incomplete. The whole thing runs in under 10 seconds."

---

### [0:40–1:00] DEMO SETUP

*[Screen: VS Code showing `vuln_app/computil/__init__.py`]*

> "This is our demo target. We have a Flask app with three classic vulnerabilities —
> SQL injection, IDOR, a hardcoded secret. But the interesting one is this:
> **computil** — a fake compression library.
>
> Look at what it does at import time: opens a socket, decodes a base64 payload,
> reads `HOME` and `USER` from the environment. Exactly the XZ Utils pattern.
>
> The maintainer account is 22 days old with one commit. Let's see what WATCHDOG makes of it."

---

### [1:00–1:30] RUNNING THE SCAN

*[Screen: Terminal, run `python scripts/test_pipeline.py --target vuln_app/`]*

> "I'll run the headless pipeline. Watch the agent log."

*[Let the pipeline run — ~5 seconds. Point to key lines as they appear:]*

> - "[scanner] 4 findings retained, 1 skipped — it correctly filtered `test_auth.py`"
> - "[trust_analyst] computil: score=0.00, CRITICAL — 22-day-old account, 1 commit"  
> - "[threat_correlator] CRITICAL — matched XZ Utils 2024 pattern, flagged for deeper analysis"
> - "[patch_writer] IDOR Pass 1: @login_required OMITTED — **watch for the rejection**"
> - "[reviewer] ✗ REJECTED — '@login_required decorator is missing. Defence-in-depth requires...'"
> - "[router] ↩ Routing back to patch_writer — correction cycle 1"
> - "[patch_writer] applying corrected patch"
> - "[reviewer] ✅ APPROVED — all 4 patches"

---

### [1:30–1:50] THE SELF-CORRECTION MOMENT ← CLIMAX

*[Screen: zoom in on the rejection and re-approval lines in the terminal]*

> "Here's the moment that makes WATCHDOG unique.
>
> The Patch Writer generated an IDOR fix — it added an ownership check.
> But it forgot the `@login_required` decorator. That's defence-in-depth:
> you need *both* layers.
>
> The Reviewer caught it automatically. Issued a correction mandate.
> The Patch Writer re-ran, added the decorator — and the Reviewer approved.
>
> **No human intervention. The system corrected itself.**
> Correction count: 1."

---

### [1:50–2:20] THE REPORT

*[Screen: open `watchdog_report.html` in browser]*

> "Here's the generated security advisory."

*[Click through tabs:]*

**Summary tab:**
> "Executive summary — one CRITICAL package, correction cycle highlighted in purple,
> trust score bar for computil showing 0.00 out of 1.00."

**Findings tab:**
> "Each finding has its full context: code snippet, threat assessment, capability
> fingerprint showing Network=YES, Base64=YES, Env=YES for computil,
> and the maintainer trust breakdown."

**Patches tab:**
> "The IDOR patch shows the purple 'CORRECTED' badge — it went through a rejection
> and correction. The rejection reason is displayed. The final approved patch with
> `@login_required` is shown in the diff."

---

### [2:20–2:42] WHAT SETS US APART

*[Screen: split — Snyk/Dependabot logos on left, WATCHDOG on right]*

> "Snyk tells you a package has a known CVE. WATCHDOG tells you a package
> *behaves like* a supply chain attack — **before any CVE exists**.
>
> We combine behavioral fingerprinting, semantic vector search against historical
> attacks, maintainer trust scoring, and an adversarial self-correcting patch
> review loop — all running locally, offline, in under 10 seconds.
>
> No cloud. No API keys. No vendor lock-in. Fully open-source."

---

### [2:42–3:00] CLOSE

*[Screen: WATCHDOG logo / title slide]*

> "WATCHDOG — the supply chain threat intelligence agent that detects what CVE
> scanners can't see.
>
> Built in 5 days for the IIT Bombay Hack & Break hackathon.
> Agentic AI × Cybersecurity.
>
> Thank you."

---

## Recording Notes

| Segment | Backup |
|---------|--------|
| Live pipeline run (1:00–1:30) | Pre-record and cut in if Ollama is slow |
| Browser report (1:50–2:20) | Use `watchdog_report.html` from pre-run |
| Full demo | Keep a backup video file `demo_backup.mp4` |

**Fallback plan:** If Ollama is slow during live demo, switch to `--no-llm` mode.
The pipeline still produces all outputs deterministically in ~2 seconds.
