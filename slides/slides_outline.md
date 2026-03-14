# 🐕 WATCHDOG — 10-Slide Presentation Outline

**Event:** IIT Bombay Hack & Break · Agentic AI × Cybersecurity  
**Duration:** 5 minutes + Q&A  
**Tone:** Confident, demo-driven, technically precise

---

## Slide 1 — Title

**Visual:** WATCHDOG logo on dark background, subtle network-graph animation
**Text:**

```
🐕 WATCHDOG
Autonomous Software Supply Chain Threat Intelligence Agent

Detects zero-day attacks before any CVE exists

[Team Name]  ·  IIT Bombay Hack & Break 2025
```

**Speaker notes:**
> "We built WATCHDOG to solve one of the most dangerous gaps in software security today."

---

## Slide 2 — The Problem (30 seconds)

**Visual:** XZ Utils attack timeline graphic — attacker's 2-year trust-building arc

**Heading:** *The attack that broke every scanner*

**Bullets:**
- XZ Utils 2024 (CVE-2024-3094): backdoor in a compression library used by every Linux distro
- Attacker spent 2 years building trust before inserting malicious code
- Payload hidden in binary test files — no static analysis caught it
- SSH authentication bypassed in affected systems

**Key stat (large text):**
```
0 / 50+ security tools detected it before disclosure
```

**Speaker notes:**
> "Every existing tool was blind. Because they're all asking the wrong question."

---

## Slide 3 — Why Existing Tools Fail

**Visual:** Two columns with logos
```
REACTIVE (detect after CVE)        PROACTIVE (but limited)
───────────────────────────        ────────────────────────
Snyk           Dependabot           SCA scanners
OSV Scanner    npm audit            SAST tools
GitHub Alerts  Safety               Trivy
```

**Heading:** *They all wait for the CVE*

**Bullets:**
- Match against known vulnerability databases (CVEs, GHSA)
- Average CVE-to-patch window: **15 days**
- XZ Utils: malicious for **weeks** before CVE-2024-3094 was assigned
- No tool monitors *behavioural change* between package versions
- No tool scores *maintainer provenance* in real time

**Speaker notes:**
> "The question isn't 'is this in the database?' It's 'does this code *behave* like an attack?'"

---

## Slide 4 — The WATCHDOG Solution

**Visual:** Clean 7-node pipeline diagram (arrows flowing left to right)

```
Scanner → Code Analyst → Trust Analyst → Threat Correlator
                                               ↓
                               Report ← Reviewer ↔ Patch Writer
                                              ↑
                                    (self-correction loop)
```

**Heading:** *7 agents, one goal: catch attacks before CVEs*

**Bullets:**
- **Behavioural fingerprinting** — not signature matching
- **Semantic similarity** — ChromaDB search against XZ Utils, PyTorch, etc.
- **Maintainer provenance** — trust score from account age, commit history, anomalies
- **Self-correcting patches** — adversarial review loop catches incomplete fixes
- **Runs fully offline** — no cloud APIs, no vendor lock-in

---

## Slide 5 — How It Works (Technical Deep Dive)

**Visual:** Annotated architecture with data types at each edge

**Heading:** *From code to verdict in < 10 seconds*

| Agent | Input | Output | Key Technology |
|-------|-------|--------|---------------|
| Scanner | File path | `FindingRecord[]` | Bandit + custom AST |
| Code Analyst | Findings | `CapabilityFingerprint[]` | Python AST visitor |
| Trust Analyst | Findings | `TrustSignal[]` | Rule-based + Ollama |
| Threat Correlator | FPs + Trust | `ThreatAssessment[]` | ChromaDB + cosine sim |
| Patch Writer | Assessments | `PatchProposal[]` | Rule-based templates |
| Reviewer | Proposals | `ReviewVerdict[]` | Deterministic + LLM |
| Reporter | Full state | HTML + Markdown | Jinja2 |

**Bullets:**
- LangGraph StateGraph manages all state and conditional routing
- Pydantic v2 models enforce type safety at every agent boundary
- ChromaDB + sentence-transformers: semantic search (no keyword matching)

---

## Slide 6 — The Self-Correction Loop ← CENTREPIECE

**Visual:** Flowchart highlighting the rejection → correction → approval arc

```
Patch Writer
     │
     ▼
  Reviewer ──── FAIL ────► CorrectionMandate
     │                            │
   PASS                    Patch Writer (v2)
     │                            │
  Report ◄────────────── Reviewer PASS
```

**Heading:** *The moment that makes WATCHDOG unique*

**Demo excerpt (screenshot or live):**
```
[reviewer]  ✗ REJECTED: @login_required decorator missing.
            Defence-in-depth requires authentication at the
            framework level AND ownership check.
[router]    ↩ Routing to patch_writer (cycle 1/2)
[patch_writer] Applying corrected patch (with @login_required)
[reviewer]  ✅ APPROVED — all 4 patches
```

**Bullets:**
- Catches incomplete patches automatically (no human review needed)
- Deterministic rules run first (fast, reliable): SQL param check, `@login_required`, env var secrets
- Optional LLM adversarial review via Ollama (red-team prompt)
- Maximum 2 correction cycles (configurable)

---

## Slide 7 — Live Demo Highlights

**Visual:** Screenshots of the Gradio UI and HTML report

**Left panel — UI:**
- Target path input: `vuln_app/`
- LLM toggle, Run button
- Real-time agent log streaming

**Right panel — Report:**
- ⛔ CRITICAL banner for `computil`
- Trust score bar: 0.00 (red)
- `🔄 CORRECTED` badge on IDOR patch
- Capability fingerprint flags: Network=YES, Base64=YES, Env=YES

**Key numbers on slide:**
```
4 findings detected
1 CRITICAL (computil — XZ Utils pattern)
1 self-correction cycle
All 4 patches approved
< 8 seconds total runtime
```

---

## Slide 8 — Technology Stack

**Visual:** Logo grid with clean spacing

```
LangGraph        Pydantic v2      ChromaDB
(orchestration)  (type safety)    (vector search)

Bandit + AST     Ollama + Mistral sentence-transformers
(static analysis)(local LLM)     (embeddings)

Gradio           Jinja2           Rich
(web UI)         (templates)      (terminal output)
```

**Heading:** *Fully offline · Open source · No cloud APIs*

**Bullets:**
- Zero external API calls — runs on a laptop
- Python 3.11+ — modern type system, TypedDict state
- Everything installable with `pip install -e .` or `uv sync`
- Demo target: intentionally vulnerable Flask app with 4 real vulnerability patterns

---

## Slide 9 — Impact & Market

**Visual:** Market sizing graphic + attack frequency chart

**Heading:** *Every company that uses open-source software needs this*

**Statistics:**
- **96%** of codebases contain open-source components (Synopsys 2024)
- **245%** YoY increase in software supply chain attacks (Sonatype 2023)
- **$10B+** estimated market for software supply chain security
- Average breach cost from supply chain attack: **$4.4M** (IBM 2024)

**WATCHDOG's edge:**
| | Snyk / Dependabot | WATCHDOG |
|-|-------------------|---------|
| Detects before CVE | ❌ | ✅ |
| Behavioural analysis | ❌ | ✅ |
| Maintainer trust | ❌ | ✅ |
| Self-correcting patches | ❌ | ✅ |
| Offline / private | ❌ | ✅ |

---

## Slide 10 — Roadmap & Call to Action

**Visual:** Timeline arrow with milestone icons

**Heading:** *What's next for WATCHDOG*

**Roadmap:**
```
Now  →  PyPI / npm real-time registry monitoring
+30d →  GitHub Actions integration (CI/CD gate)
+60d →  Multi-language support (Go, Rust, Java)
+90d →  Federated attack-pattern knowledge sharing
+6m  →  SaaS platform for security teams
```

**What we want from the judges:**
- Feedback on the self-correction loop architecture
- Connections to security teams who can provide real attack-pattern datasets
- Guidance on responsible disclosure / open-sourcing the knowledge base

**Close:**
```
🐕 WATCHDOG
github.com/your-org/watchdog

"The best time to detect a supply chain attack
 is before the CVE exists."
```

---

## Presentation Tips

- **Slide 6 (self-correction):** Spend the most time here — this is the differentiator
- **Demo backup:** Have `watchdog_report.html` pre-generated and open in a tab
- **If questioned on LLM accuracy:** Emphasise that deterministic rules run first — LLM is additive, not load-bearing
- **If questioned on scalability:** ChromaDB can hold thousands of attack patterns; scanning is O(n) in file count
