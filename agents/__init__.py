"""
agents/__init__.py
------------------
Public API for the WATCHDOG agent package.

Exports one LangGraph node function per agent — these are the callables
that workflow/graph.py registers as graph nodes.
"""

from agents.scanner           import run_scanner
from agents.code_analyst      import run_code_analyst
from agents.trust_analyst     import run_trust_analyst
from agents.threat_correlator import run_threat_correlator
from agents.patch_writer      import run_patch_writer
from agents.reviewer          import run_reviewer
from agents.reporter          import run_reporter

__all__ = [
    "run_scanner",
    "run_code_analyst",
    "run_trust_analyst",
    "run_threat_correlator",
    "run_patch_writer",
    "run_reviewer",
    "run_reporter",
]
