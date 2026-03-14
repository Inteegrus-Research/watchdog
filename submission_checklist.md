# 🐕 WATCHDOG — Submission Checklist

Complete every item before submitting on Unstop.  
Mark each `[ ]` as `[x]` when done.

---

## 📁 Code & Repository

- [ ] Repository created on GitHub (public or private with judge access)
- [ ] All code committed and pushed:
  ```bash
  git add -A && git commit -m "feat: Day 5 final polish" && git push
  ```
- [ ] `.gitignore` excludes: `chroma_db/`, `__pycache__/`, `.venv/`, `reports/`, `.env`
- [ ] No API keys or secrets in committed code
- [ ] `pyproject.toml` lists all dependencies with minimum versions
- [ ] All Python files have docstrings and type annotations

---

## 📦 Dependencies & Environment

- [ ] Python ≥ 3.11 confirmed:
  ```bash
  python --version   # should show 3.11.x or 3.12.x
  ```
- [ ] Dependencies install cleanly:
  ```bash
  pip install -e .   # or: uv sync
  ```
- [ ] Bandit available:
  ```bash
  python -m bandit --version
  ```
- [ ] (Optional) Ollama running and model pulled:
  ```bash
  ollama list        # should show mistral
  ```

---

## 🗄️ Data & Knowledge Base

- [ ] ChromaDB seeded with attack patterns:
  ```bash
  python data/seed_chromadb.py
  # Expected: "Seeded 2 attack patterns. Smoke-test query successful."
  ```
- [ ] `chroma_db/` directory created at project root
- [ ] `data/metadata/maintainer_fake.json` present (computil entry with trust_score=0.08)
- [ ] `data/attack_patterns/xz_utils_2024.txt` present
- [ ] `data/attack_patterns/pytorch_2022.txt` present

---

## 🔬 Demo App

- [ ] `vuln_app/app.py` contains 3 vulnerabilities (SQLi, IDOR, hardcoded secret)
- [ ] `vuln_app/computil/__init__.py` contains backdoor simulation
- [ ] `vuln_app/test_auth.py` is present (decoy — should be filtered by scanner)
- [ ] Demo app runs:
  ```bash
  cd vuln_app && python app.py
  # → Running on http://localhost:5001
  ```

---

## 🧪 Pipeline Tests

- [ ] Headless pipeline runs without errors:
  ```bash
  python scripts/test_pipeline.py --target vuln_app/
  # Expected output:
  #   findings=4  fingerprints=2  trust_signals=2
  #   correction_count=1  all_approved=True
  #   ✓ Day 3 Test Passed
  ```
- [ ] IDOR rejection and self-correction verified (correction_count == 1)
- [ ] computil trust score < 0.30 (CRITICAL)
- [ ] `test_auth.py` not included in findings (filtered correctly)
- [ ] (Optional, if Ollama available) LLM enrichment works:
  ```bash
  python scripts/test_pipeline.py --target vuln_app/ --llm
  ```

---

## 🌐 Web UI

- [ ] Gradio UI launches:
  ```bash
  python webui/app.py
  # → http://localhost:7860
  ```
- [ ] Entering `vuln_app/` and clicking "Run" executes the pipeline
- [ ] Agent log streams in real time
- [ ] HTML report renders in the Report tab
- [ ] Download button generates a file named `*_watchdog_report.html`
- [ ] Error message shown if invalid target path entered

---

## 📊 HTML Report

- [ ] `watchdog_report.html` generated at project root
- [ ] Opens correctly in Chrome/Firefox/Safari (dark theme)
- [ ] Summary tab shows: executive alert, metric cards, threat table, verdict table
- [ ] Findings tab shows: collapsible cards with code snippets, trust bars, capability flags
- [ ] Patches tab shows: IDOR patch with 🔄 CORRECTED badge and purple border
- [ ] Patches tab shows: computil with ⛔ remove_dependency alert
- [ ] Raw Data tab shows: trust signals, fingerprints, threat assessments
- [ ] Report is self-contained (works offline, no CDN dependencies)

---

## 📝 Documentation

- [ ] `README.md` complete with: overview, architecture diagram, installation, usage, project structure
- [ ] `scripts/demo_video_script.md` ready for recording
- [ ] `slides/slides_outline.md` content for all 10 slides
- [ ] Code comments explain non-obvious decisions
- [ ] `run_demo.sh` works end-to-end:
  ```bash
  chmod +x scripts/run_demo.sh && bash scripts/run_demo.sh
  ```

---

## 🎬 Video & Slides

- [ ] Demo video recorded (MP4, ≤ 5 minutes)
  - Opening hook (XZ Utils problem): 0:00–0:18
  - WATCHDOG overview: 0:18–0:40
  - Live scan demo: 1:00–1:30
  - Self-correction moment highlighted: 1:30–1:50
  - HTML report walkthrough: 1:50–2:20
  - Closing: 2:42–3:00
- [ ] Backup video recorded (full pipeline run, no commentary)
- [ ] Slide deck prepared (PDF or PPTX, 10 slides)
  - Title, Problem, Existing tools fail, Solution, Architecture
  - Self-Correction Loop, Demo, Tech stack, Impact, Roadmap
- [ ] Slide deck exported to PDF

---

## 📋 Abstract (150–300 words)

Draft abstract template (edit before submission):

> WATCHDOG is an autonomous multi-agent AI system that detects zero-day software
> supply chain attacks before any CVE is assigned. Unlike existing tools (Snyk,
> Dependabot, OSV Scanner) that match against known vulnerability databases,
> WATCHDOG asks: "Does this package *behave* like a supply chain attack?"
>
> The system runs seven specialised agents in a LangGraph state machine:
> a Scanner (Bandit + custom AST analysis), a Code Analyst (capability fingerprinting),
> a Trust Analyst (maintainer provenance scoring), a Threat Correlator (ChromaDB
> semantic similarity search against historical attacks including XZ Utils 2024 and
> PyTorch-nightly 2022), a Patch Writer (rule-based remediation generation),
> an adversarial Reviewer (deterministic rules + optional Ollama LLM review),
> and a Report Generator (Jinja2 HTML advisory).
>
> WATCHDOG's signature feature is its self-correcting patch loop: when the Reviewer
> rejects a patch for security deficiencies, it issues a structured CorrectionMandate
> and the Patch Writer automatically re-generates an improved version. This loop
> demonstrated catching a missing `@login_required` decorator in an IDOR fix,
> correcting and approving it without human intervention.
>
> The system runs entirely offline (Ollama + ChromaDB + sentence-transformers),
> requires no cloud APIs, and processes a typical Python project in under 10 seconds.
> In testing against our deliberately vulnerable demo application, WATCHDOG correctly
> identified a simulated XZ Utils-style backdoor package (trust_score=0.00, CRITICAL
> risk), detected all three classic vulnerabilities, and self-corrected one rejected
> patch — demonstrating the complete agentic AI pipeline.

- [ ] Abstract saved to `submission_abstract.txt`
- [ ] Word count: 150–300 words ✓

---

## 🚀 Unstop Submission

- [ ] Account created / logged in at unstop.com
- [ ] Team registered for IIT Bombay Hack & Break
- [ ] GitHub repository URL submitted
- [ ] Demo video uploaded / linked
- [ ] Slide deck uploaded
- [ ] Abstract pasted in the text field
- [ ] Submission confirmed (screenshot taken as proof)
- [ ] Submitted **before the deadline**

---

## 🔥 Final Smoke Test (run 30 minutes before demo)

```bash
# 1. Clean run from scratch
rm -rf chroma_db/ reports/ watchdog_report.html __pycache__
python data/seed_chromadb.py

# 2. Headless pipeline test
python scripts/test_pipeline.py --target vuln_app/

# 3. Check report exists and is non-trivial
ls -lh watchdog_report.html   # should be ~40KB+

# 4. Launch UI
python webui/app.py &
# Open http://localhost:7860 and run a scan
```

**Expected console output:**
```
[scanner]           4 finding(s) retained, 1 skipped
[trust_analyst]     computil: score=0.00  risk=CRITICAL
[threat_correlator] computil: CRITICAL  sim=0.650  deeper=True
[reviewer]          ✗ REJECTED: @login_required missing
[router]            ↩ Routing to patch_writer (cycle 1/2)
[reviewer]          ✅ APPROVED: all 4 patches
[reporter]          Report saved: reports/.../watchdog_report.html
✓ Day 3 Test Passed
```

---

*Good luck! The self-correction loop is the demo's climax — make sure it's clearly visible.*
