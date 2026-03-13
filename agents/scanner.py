"""
agents/scanner.py
-----------------
Scanner Agent — Day 2 implementation target.

Responsibilities:
  1. Walk the target_path directory tree, filtering out test files and
     virtual-environment directories (using utils.file_utils helpers).
  2. Run Bandit (via subprocess) over every non-test Python file and
     parse the JSON output into FindingRecord objects.
  3. Run the custom AST extractor (utils.ast_extractor) for capability
     signals that Bandit misses: new imports, socket calls, base64 usage.
  4. Return the populated list of FindingRecord objects in state.

Inputs  (from WatchdogState):
  - target_path: str

Outputs (written to WatchdogState):
  - findings: List[FindingRecord]
"""

from __future__ import annotations

# Day 2 imports (uncomment when implementing):
# import json
# import subprocess
# from schemas.models import FindingRecord
# from utils.ast_extractor import extract_capabilities
# from utils.file_utils import is_test_file, list_python_files
# from workflow.state import WatchdogState


def run_scanner(state: dict) -> dict:
    """
    LangGraph node function for the Scanner Agent.

    Placeholder — returns state unchanged.
    Full implementation on Day 2.
    """
    print(f"[scanner] Scanning: {state.get('target_path', 'unknown')}")
    # TODO Day 2: invoke Bandit + AST extractor, populate state["findings"]
    return {}
