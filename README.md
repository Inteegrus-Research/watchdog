# 🐕 WATCHDOG
### Autonomous Software Supply Chain Threat Intelligence Agent

> *"Every line of open-source code you import is a door you left unlocked.  
> WATCHDOG is the only agent that watches who's walking through it."*

---

## What is WATCHDOG?

WATCHDOG is a multi-agent AI system that detects zero-day software supply chain attacks **before any CVE exists** — reasoning about *behavior, context, and intent*, not just version numbers.

It models the threat class that caught SolarWinds, PyTorch-nightly, and XZ Utils:
a malicious package update that looks legitimate to every existing scanner but
introduces subtle new capabilities (network connections, base64 payloads, modified
install hooks) that reveal its true purpose to a sufficiently deep analyst.

WATCHDOG is that analyst, running at machine speed.

---

## Architecture (5-Agent Pipeline)

```
[Scanner Agent] → [Code Analyst] → [Trust Analyst] → [Threat Correlator]
                                                              ↓
                                              [Critic ↔ Patch Writer loop]
                                                              ↓
                                                    [Report Generator]
```

| Agent | Responsibility |
|-------|---------------|
| **Scanner** | Bandit + AST analysis; emits `FindingRecord` objects |
| **Code Analyst** | Semantic reasoning about new capabilities via LLM |
| **Trust Analyst** | Maintainer provenance — account age, commit history, anomalies |
| **Threat Correlator** | ChromaDB semantic search against 15 historical attacks |
| **Critic + Patch Writer** | Self-correcting remediation loop (max 2 retries) |
| **Report Generator** | Renders full security advisory in Markdown + HTML |

---

## Quick Start

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- [Ollama](https://ollama.ai/) running locally with `llama3` or `mistral` pulled

### 1. Clone & install

```bash
git clone https://github.com/your-org/watchdog.git
cd watchdog

# Using uv (recommended)
uv sync

# OR using pip
pip install -e ".[dev]"
```

### 2. Pull the Ollama model

```bash
ollama pull llama3
# or
ollama pull mistral
```

### 3. Seed the ChromaDB knowledge base

```bash
python data/seed_chromadb.py
```

This embeds the XZ Utils and PyTorch attack patterns into a local vector store.
You should see:

```
[WATCHDOG Seed] Collection 'attack_patterns' created.
[WATCHDOG Seed] Inserted 2 documents into ChromaDB.
[WATCHDOG Seed] Smoke-test query: 'compression library backdoor ...'
  ✓ Top result ID   : xz_utils_2024
  ✓ Attack name     : XZ Utils Supply Chain Compromise (2024)
  ✓ Distance score  : 0.1823
[WATCHDOG Seed] ChromaDB seeding complete ✓
```

### 4. Run the demo

```bash
bash scripts/run_demo.sh
# or
python scripts/test_pipeline.py
```

### 5. Launch the Web UI

```bash
python webui/app.py
```

Open [http://localhost:7860](http://localhost:7860) in your browser.

---

## Scanning the Vulnerable Demo App

The `vuln_app/` directory contains a deliberately insecure Flask application.
Point WATCHDOG at it to see a full detection run:

```bash
python scripts/test_pipeline.py --target vuln_app/
```

WATCHDOG will detect (and explain) all three intentional vulnerabilities:

| # | Vulnerability | Type | Severity |
|---|--------------|------|----------|
| 1 | `/login` — SQL injection via string concat | SQLI | HIGH |
| 2 | `/delete_note/<id>` — no ownership check | IDOR | MEDIUM |
| 3 | `app.secret_key = "super_secret_..."` | Hardcoded Secret | HIGH |

> Note: `vuln_app/test_auth.py` is **intentionally excluded** by the Scanner Agent
> because it matches the `test_*.py` filter rule.

---

## Project Structure

```
watchdog/
├── agents/          # Agent implementations (Days 2-4)
├── workflow/        # LangGraph state machine
│   ├── state.py     # Shared TypedDict state
│   └── graph.py     # Graph assembly + routing
├── utils/           # Shared helpers (AST, ChromaDB, file I/O)
├── schemas/         # Pydantic data models
├── data/            # Attack patterns + metadata + seed script
├── templates/       # Jinja2 report templates
├── webui/           # Gradio web interface
├── vuln_app/        # Deliberately vulnerable Flask app (scan target)
└── scripts/         # Test + demo scripts
```

---

## Development Roadmap

| Day | Focus |
|-----|-------|
| **Day 1** ✅ | Schemas, LangGraph skeleton, ChromaDB seeding, vuln app |
| **Day 2** | Scanner Agent + Code Analyst Agent (Bandit + AST + LLM) |
| **Day 3** | Trust Analyst + Threat Correlator + Patch Writer + Critic |
| **Day 4** | Report Generator + Jinja2 templates + Gradio Web UI |
| **Day 5** | Polish, demo recording, pitch deck |

---

## Screenshot

> _(Coming Day 4 — after the Gradio UI is built)_

---

## License

MIT — see [LICENSE](LICENSE) for details.
