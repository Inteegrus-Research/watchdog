#!/usr/bin/env bash
# scripts/run_demo.sh
# -------------------
# WATCHDOG Day 1 demo runner.
# Runs the full setup sequence and then executes the pipeline smoke test.
#
# Usage:
#   bash scripts/run_demo.sh
#   bash scripts/run_demo.sh --skip-seed   (if ChromaDB already seeded)

set -euo pipefail

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Navigate to project root (one level up from scripts/) ─────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

echo -e "${CYAN}${BOLD}"
echo "  ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗██████╗  ██████╗  ██████╗ "
echo "  ██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║██╔══██╗██╔═══██╗██╔════╝ "
echo "  ██║ █╗ ██║███████║   ██║   ██║     ███████║██║  ██║██║   ██║██║  ███╗"
echo "  ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║██║  ██║██║   ██║██║   ██║"
echo "  ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║██████╔╝╚██████╔╝╚██████╔╝"
echo "   ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝ "
echo -e "${RESET}"
echo -e "${CYAN}  Autonomous Supply Chain Threat Intelligence Agent${RESET}"
echo -e "${CYAN}  IIT Bombay Hack & Break · Agentic AI × Cybersecurity${RESET}"
echo ""

# ── Step 1: Check Python version ──────────────────────────────────────────────
echo -e "${BOLD}[1/5] Checking Python version...${RESET}"
python_version=$(python3 --version 2>&1 | awk '{print $2}')
required_minor=11
actual_minor=$(echo "$python_version" | cut -d. -f2)
if [ "$actual_minor" -lt "$required_minor" ]; then
  echo -e "${RED}ERROR: Python 3.${required_minor}+ required. Found: ${python_version}${RESET}"
  exit 1
fi
echo -e "  ${GREEN}✓ Python ${python_version}${RESET}"

# ── Step 2: Check Ollama ───────────────────────────────────────────────────────
echo -e "\n${BOLD}[2/5] Checking Ollama...${RESET}"
if command -v ollama &>/dev/null; then
  echo -e "  ${GREEN}✓ Ollama found${RESET}"
  if ollama list 2>/dev/null | grep -q "llama3\|mistral"; then
    echo -e "  ${GREEN}✓ LLM model available${RESET}"
  else
    echo -e "  ${YELLOW}⚠ No llama3/mistral model found. Run: ollama pull llama3${RESET}"
  fi
else
  echo -e "  ${YELLOW}⚠ Ollama not found. Install from https://ollama.ai/ for full pipeline.${RESET}"
  echo -e "  ${YELLOW}  Day 1 skeleton will still run without it.${RESET}"
fi

# ── Step 3: Seed ChromaDB ─────────────────────────────────────────────────────
SKIP_SEED=false
for arg in "$@"; do
  [[ "$arg" == "--skip-seed" ]] && SKIP_SEED=true
done

echo -e "\n${BOLD}[3/5] Seeding ChromaDB...${RESET}"
if [ "$SKIP_SEED" = true ]; then
  echo -e "  ${YELLOW}⚠ Skipping seed (--skip-seed flag)${RESET}"
else
  if python3 data/seed_chromadb.py; then
    echo -e "  ${GREEN}✓ ChromaDB seeded successfully${RESET}"
  else
    echo -e "  ${RED}✗ ChromaDB seeding failed. Check dependencies: pip install chromadb sentence-transformers${RESET}"
    echo -e "  ${YELLOW}  Continuing anyway (smoke test will warn about empty collection)${RESET}"
  fi
fi

# ── Step 4: Validate imports ──────────────────────────────────────────────────
echo -e "\n${BOLD}[4/5] Validating project imports...${RESET}"
if python3 -c "
from schemas.models import FindingRecord, ExploitAssessment, PatchProposal
from workflow.state import make_initial_state
from workflow.graph import watchdog_graph
from utils.file_utils import file_exists, read_file
from utils.ast_extractor import extract_capabilities_from_source
print('All imports OK')
"; then
  echo -e "  ${GREEN}✓ All imports resolved${RESET}"
else
  echo -e "  ${RED}✗ Import errors. Run: pip install -e .${RESET}"
  exit 1
fi

# ── Step 5: Run pipeline smoke test ───────────────────────────────────────────
echo -e "\n${BOLD}[5/5] Running pipeline smoke test...${RESET}"
python3 scripts/test_pipeline.py --target vuln_app/

echo ""
echo -e "${GREEN}${BOLD}════════════════════════════════════════════════"
echo -e "  WATCHDOG Day 1 setup complete ✓"
echo -e "════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  Next steps:"
echo -e "  ${CYAN}• Launch Web UI:${RESET}   python webui/app.py"
echo -e "  ${CYAN}• Scan vuln app:${RESET}  python scripts/test_pipeline.py --target vuln_app/"
echo -e "  ${CYAN}• Day 2 focus:${RESET}    Implement Scanner + Code Analyst agents"
echo ""
