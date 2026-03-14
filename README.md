<div align="center">

# 🐕 WATCHDOG

### Autonomous Software Supply Chain Threat Intelligence Agent

*Detects zero-day supply chain attacks before any CVE exists*

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)
[![LangGraph](https://img.shields.io/badge/LangGraph-multi--agent-green.svg)](https://langchain-ai.github.io/langgraph/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Hackathon: IIT Bombay Hack & Break](https://img.shields.io/badge/hackathon-IIT%20Bombay-red.svg)](#)

</div>

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Self-Correction Loop](#self-correction-loop)
4. [Quick Start](#quick-start)
5. [Installation](#installation)
6. [Usage](#usage)
7. [Project Structure](#project-structure)
8. [Demo App](#demo-app)
9. [Example Output](#example-output)
10. [Technology Stack](#technology-stack)
11. [Acknowledgments](#acknowledgments)

---

## Overview

WATCHDOG is a **multi-agent AI system** that detects zero-day software supply chain attacks
*before any CVE is published* — at the moment a malicious package version lands in a registry.

Traditional tools (Snyk, Dependabot, OSV) are reactive: they alert only after a vulnerability
has been reported, catalogued, and assigned a CVE. The XZ Utils 2024 backdoor (CVE-2024-3094)
evaded all scanners for weeks after being live. **WATCHDOG fills this gap.**

### How it works

Instead of matching against known vulnerability databases, WATCHDOG asks:
*"Does this package behave like a previous supply chain attack?"*

It analyses **code capabilities** (new network calls, base64 payloads, subprocess execution),
**maintainer provenance** (account age, commit history, suspicious takeovers), and performs
**semantic similarity search** against a knowledge base of historical attacks (XZ Utils, PyTorch
dependency confusion, and others). An adversarial Reviewer Agent then checks every proposed
fix — and if it finds a deficiency, the system self-corrects without human intervention.

---

## Architecture

```
Target codebase
      │
      ▼
┌─────────────┐
│  A1 Scanner │  Bandit static analysis + AST capability extractor
└──────┬──────┘  → List[FindingRecord]
       │
       ▼
┌──────────────────┐     ┌──────────────────┐
│  A2 Code Analyst │     │  A3 Trust Analyst │
│  CapabilityFP    │     │  Maintainer trust │  (run in parallel)
└──────┬───────────┘     └────────┬──────────┘
       └──────────┬───────────────┘
                  ▼
       ┌──────────────────────┐
       │  A4 Threat Correlator│  ChromaDB semantic search
       │  vs historical attacks│  + trust-score adjustment
       └──────────┬───────────┘
                  ▼
       ┌──────────────────────┐
       │  A5 Patch Writer     │  Rule-based fix generation
       └──────────┬───────────┘
                  ▼
       ┌──────────────────────┐
       │  A6 Reviewer (Critic)│  Deterministic rules + LLM adversarial review
       └──────────┬───────────┘
                  │
         ┌────────┴────────────────┐
         │ Rejected & retries left?│
         │    YES → A5 (retry)     │  ← self-correction loop
         │    NO  → A7             │
         └─────────────────────────┘
                  ▼
       ┌──────────────────────┐
       │  A7 Report Generator │  Jinja2 HTML + Markdown advisory
       └──────────────────────┘
```

All agents share a **LangGraph TypedDict state** — every node reads from and writes back to
the same state, enabling the conditional self-correction loop to operate cleanly.

---

## Self-Correction Loop

WATCHDOG's signature feature is its **adversarial self-correction loop**:

1. The **Reviewer Agent** runs two layers of checks on every patch:
   - **Deterministic rules** (always, fast): parameterised SQL check, `@login_required` check,
     env-var secret check, syntax validation
   - **LLM adversarial review** (optional, Ollama): red-team "find anything wrong" prompt

2. If a patch fails, the Reviewer emits a `CorrectionMandate` with specific instructions.

3. The graph routes back to the Patch Writer, which reads the mandate and re-generates.

4. This repeats up to **`MAX_CORRECTION_CYCLES = 2`** times.

**Demo:** The IDOR patch is intentionally generated without `@login_required` on pass 1.
The Reviewer catches this, issues a mandate, and the corrected patch (with the decorator)
is approved on pass 2. The HTML report highlights the correction in purple.

---

## Quick Start

```bash
# 1. Clone and set up
git clone https://github.com/your-org/watchdog.git
cd watchdog
pip install -e ".[dev]"

# 2. Seed the ChromaDB attack-pattern knowledge base
python data/seed_chromadb.py

# 3. (Optional) Pull LLM models for enrichment
ollama pull mistral

# 4. Launch the Web UI
python webui/app.py
# → Open http://localhost:7860
# → Enter "vuln_app/" → Click "Run WATCHDOG Scan"

# 5. Or run headless
python scripts/test_pipeline.py --target vuln_app/
```

---

## Installation

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | ≥ 3.11 | Required for TypedDict generics |
| Bandit | ≥ 1.7.8 | Static analysis scanner |
| Ollama | any | Optional — for LLM enrichment |
| ChromaDB | ≥ 0.5 | Vector similarity search |

### Using `uv` (recommended)

```bash
# Install uv if not already installed
curl -Lsf https://astral.sh/uv/install.sh | sh

# Sync all dependencies
uv sync

# With optional dev tools
uv sync --extra dev

source .venv/bin/activate
```

### Using `pip`

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

### Ollama setup (for LLM enrichment)

```bash
# Install Ollama from https://ollama.ai
ollama serve &               # start the Ollama daemon
ollama pull mistral          # Trust Analyst + Reviewer
```

### Seed the knowledge base

```bash
python data/seed_chromadb.py
# Seeded 2 attack patterns: XZ Utils 2024, PyTorch-nightly 2022
# Run a smoke-test query...
# ChromaDB ready at chroma_db/
```

---

## Usage

### Web UI

```bash
python webui/app.py
```

Open **http://localhost:7860**. Enter a target path, toggle LLM enrichment, click **Run**.
The report appears in the **Report** tab with a download button.

### Headless pipeline

```bash
# Basic scan (rule-based, no LLM)
python scripts/test_pipeline.py --target vuln_app/

# With Ollama LLM enrichment
python scripts/test_pipeline.py --target vuln_app/ --llm

# Show self-correction loop details
python scripts/test_pipeline.py --target vuln_app/ --loop

# Verbose: dump full state JSON
python scripts/test_pipeline.py --target vuln_app/ --verbose

# Scan a different target
python scripts/test_pipeline.py --target /path/to/your/project
```

### Individual agents

```bash
# Run only the scanner
python agents/scanner.py vuln_app/

# Run code analyst on scanner output
python agents/code_analyst.py vuln_app/

# Run full reporter standalone
python agents/reporter.py vuln_app/
# → generates watchdog_report.html
```

### Expected output

```
[scanner]         Starting scan — target: '.../vuln_app'
[scanner]         Scan complete — 4 finding(s) retained, 1 skipped (test files)
[code_analyst]    computil  [network, subprocess, base64, env_access]  ← __init__.py
[trust_analyst]   computil: score=0.00  risk=CRITICAL  anomalies=10
[threat_correlator] computil: CRITICAL  sim=0.650  deeper=True
[patch_writer]    IDOR — Pass 1: ownership check added, @login_required OMITTED
[reviewer]        ✗ REJECTED: IDOR patch is INCOMPLETE: @login_required missing
[router]          ↩ Routing to patch_writer (cycle 1/2)
[patch_writer]    IDOR — applying corrected patch
[reviewer]        ✅ APPROVED: vuln_app
[reporter]        Report saved: reports/20250101_120000/watchdog_report.html
```

---

## Project Structure

```
watchdog/
├── agents/                   # Agent implementations (one file per agent)
│   ├── scanner.py            # A1: Bandit + AST analysis
│   ├── code_analyst.py       # A2: CapabilityFingerprint builder
│   ├── trust_analyst.py      # A3: Maintainer provenance scoring
│   ├── threat_correlator.py  # A4: ChromaDB semantic similarity
│   ├── patch_writer.py       # A5: Rule-based patch generation
│   ├── reviewer.py           # A6: Deterministic + LLM adversarial review
│   └── reporter.py           # A7: Jinja2 HTML/Markdown report
│
├── workflow/
│   ├── graph.py              # LangGraph StateGraph assembly
│   └── state.py              # WatchdogState TypedDict
│
├── schemas/
│   └── models.py             # Pydantic v2 data models (8 classes)
│
├── utils/
│   ├── ast_extractor.py      # AST capability visitor
│   ├── chroma_utils.py       # ChromaDB collection helpers
│   └── file_utils.py         # Path helpers
│
├── templates/
│   ├── report.html.j2        # Dark-mode HTML report template
│   └── report.md.j2          # Markdown report template
│
├── data/
│   ├── attack_patterns/      # Historical attack fingerprints
│   │   ├── xz_utils_2024.txt
│   │   └── pytorch_2022.txt
│   ├── metadata/
│   │   └── maintainer_fake.json  # Demo maintainer data
│   └── seed_chromadb.py      # One-time ChromaDB seeder
│
├── vuln_app/                 # Demo vulnerable Flask app
│   ├── app.py                # SQLi (B608), IDOR, hardcoded secret
│   ├── test_auth.py          # Decoy with credentials (filtered by scanner)
│   └── computil/
│       └── __init__.py       # Simulated backdoor package
│
├── webui/
│   └── app.py                # Gradio web interface
│
├── scripts/
│   ├── test_pipeline.py      # End-to-end headless test
│   └── run_demo.sh           # Full setup + smoke test script
│
├── slides/
│   └── slides_outline.md     # 10-slide presentation outline
│
├── chroma_db/                # ChromaDB storage (created by seed script)
├── reports/                  # Generated reports (timestamped)
├── watchdog_report.html      # Latest report (symlink / copy)
├── pyproject.toml
└── README.md
```

---

## Demo App

The `vuln_app/` directory contains a deliberately vulnerable Flask application with:

| # | Vulnerability | Type | Location |
|---|--------------|------|----------|
| 1 | SQL Injection | `sql_injection` | `app.py:83` — string concatenation in login query |
| 2 | IDOR | `idor` | `app.py:113` — no ownership check in delete endpoint |
| 3 | Hardcoded Secret | `hardcoded_secret` | `app.py:24` — Flask secret key in source |
| 4 | Backdoor | `network_call` + `base64_payload` | `computil/__init__.py` — socket + base64 at import time |

The `computil` package mimics the XZ Utils 2024 attack pattern:
new maintainer (22-day-old account, 1 commit), socket connection, base64 payload, `os.environ` access.

```bash
# Run the demo app (separate terminal)
cd vuln_app && pip install flask && python app.py
# → http://localhost:5001
```

---

## Example Output

After scanning `vuln_app/`, WATCHDOG produces:

```
┌─────────────────────────────────────────────────────────────┐
│ 🔴 CRITICAL — computil  sim=0.65  trust=0.00  → remove      │
│ 🟠 HIGH     — vuln_app  (SQLi, IDOR, hardcoded secret)       │
│                                                              │
│ Patches: 4 generated, 3 approved first pass, 1 corrected    │
│ Correction cycle: IDOR patch missing @login_required         │
│ After correction: all 4 patches approved                     │
└─────────────────────────────────────────────────────────────│
```

The full HTML report is saved to `watchdog_report.html` and `reports/<timestamp>/watchdog_report.html`.

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Agent orchestration | [LangGraph](https://langchain-ai.github.io/langgraph/) (StateGraph, conditional edges) |
| Data models | [Pydantic v2](https://docs.pydantic.dev/) (typed, validated) |
| LLM | [Ollama](https://ollama.ai/) + [Mistral 7B](https://ollama.ai/library/mistral) |
| Static analysis | [Bandit](https://bandit.readthedocs.io/) + custom AST visitor |
| Vector search | [ChromaDB](https://www.trychroma.com/) + `sentence-transformers/all-MiniLM-L6-v2` |
| Web UI | [Gradio 4](https://gradio.app/) |
| Report templating | [Jinja2](https://jinja.palletsprojects.com/) |
| Terminal output | [Rich](https://rich.readthedocs.io/) |

Everything runs **fully offline** — no cloud API calls required (LLM via Ollama, embeddings via sentence-transformers).

---

## Acknowledgments

- **Bandit** — Python security static analysis (PyCQA)
- **LangGraph** — Multi-agent state machine framework (LangChain AI)
- **ChromaDB** — Embedded vector database
- **Ollama** — Local LLM inference
- **Sentence Transformers** — Embedding models (Hugging Face)
- **XZ Utils 2024** — Real-world attack that inspired this project ([CVE-2024-3094](https://nvd.nist.gov/vuln/detail/CVE-2024-3094))
- **IIT Bombay Hack & Break** — Agentic AI × Cybersecurity track

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
<em>Built in 5 days for the IIT Bombay Hack & Break hackathon · Agentic AI × Cybersecurity</em>
</div>
