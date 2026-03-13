"""
utils/ast_extractor.py
-----------------------
Abstract Syntax Tree (AST) analysis utilities for the WATCHDOG Code Analyst Agent.

Day 1 status: foundational helpers are implemented; the full capability-extraction
logic will be completed on Day 2 when the Code Analyst Agent is wired in.

Capabilities extracted (Day 2 implementation targets):
  - New import statements (module names)
  - Socket / network call sites
  - subprocess / os.system call sites
  - os.environ / environment variable accesses
  - base64 decode / encode call sites
  - Open file operations writing outside the package directory
  - Changes to setup.py / install hooks
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field


@dataclass
class ASTFindings:
    """Container for all capability signals extracted from a single Python file."""

    file_path: str
    imports: list[str] = field(default_factory=list)
    network_calls: list[tuple[int, str]] = field(default_factory=list)   # (line, code)
    subprocess_calls: list[tuple[int, str]] = field(default_factory=list)
    env_accesses: list[tuple[int, str]] = field(default_factory=list)
    base64_calls: list[tuple[int, str]] = field(default_factory=list)
    filesystem_writes: list[tuple[int, str]] = field(default_factory=list)

    @property
    def has_suspicious_capabilities(self) -> bool:
        """Return True if any non-trivial capability was detected."""
        return bool(
            self.network_calls
            or self.subprocess_calls
            or self.base64_calls
        )


class CapabilityVisitor(ast.NodeVisitor):
    """
    AST node visitor that walks a parsed Python file and records capability signals.

    Designed to be instantiated once per file.  Call ``visit(tree)`` with the
    parsed AST, then read the ``findings`` attribute.
    """

    # Module names that indicate network capability
    NETWORK_MODULES = {"socket", "urllib", "urllib3", "requests", "httpx", "aiohttp"}
    # Module names that indicate subprocess/shell execution
    SUBPROCESS_MODULES = {"subprocess", "os", "shlex"}
    # Base64 and encoding modules
    ENCODING_MODULES = {"base64", "binascii", "codecs"}

    def __init__(self, file_path: str) -> None:
        self.findings = ASTFindings(file_path=file_path)

    # ── Import visitors ────────────────────────────────────────────────────────

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            self.findings.imports.append(alias.name)
            self._check_dangerous_import(alias.name, node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        if node.module:
            self.findings.imports.append(node.module)
            self._check_dangerous_import(node.module, node.lineno)
        self.generic_visit(node)

    def _check_dangerous_import(self, module_name: str, lineno: int) -> None:
        root = module_name.split(".")[0]
        if root in self.NETWORK_MODULES:
            self.findings.network_calls.append((lineno, f"import {module_name}"))
        if root in self.SUBPROCESS_MODULES:
            self.findings.subprocess_calls.append((lineno, f"import {module_name}"))
        if root in self.ENCODING_MODULES:
            self.findings.base64_calls.append((lineno, f"import {module_name}"))

    # ── Call visitors ──────────────────────────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        call_str = ast.unparse(node) if hasattr(ast, "unparse") else "<call>"

        # os.environ / os.getenv
        if _matches_attr(node.func, "os", "environ") or _matches_attr(node.func, "os", "getenv"):
            self.findings.env_accesses.append((node.lineno, call_str))

        # socket.socket(...)
        if _matches_attr(node.func, "socket", "socket"):
            self.findings.network_calls.append((node.lineno, call_str))

        # subprocess.Popen / subprocess.run / subprocess.call
        if isinstance(node.func, ast.Attribute) and node.func.attr in {
            "Popen", "run", "call", "check_output", "check_call"
        }:
            self.findings.subprocess_calls.append((node.lineno, call_str))

        # os.system / os.popen
        if _matches_attr(node.func, "os", "system") or _matches_attr(node.func, "os", "popen"):
            self.findings.subprocess_calls.append((node.lineno, call_str))

        # base64.b64decode / base64.b64encode
        if _matches_attr(node.func, "base64", "b64decode") or _matches_attr(
            node.func, "base64", "b64encode"
        ):
            self.findings.base64_calls.append((node.lineno, call_str))

        self.generic_visit(node)


def _matches_attr(node: ast.expr, obj_name: str, attr_name: str) -> bool:
    """Return True if *node* is an attribute access like ``obj_name.attr_name``."""
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == obj_name
        and node.attr == attr_name
    )


def extract_capabilities(file_path: str) -> ASTFindings:
    """
    Parse a Python source file and extract capability signals.

    Parameters
    ----------
    file_path : str
        Path to the .py file to analyse.

    Returns
    -------
    ASTFindings
        Populated with all detected capability signals.

    Raises
    ------
    SyntaxError
        If the file cannot be parsed as valid Python.
    FileNotFoundError
        If the file does not exist.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Source file not found: {file_path}")

    with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
        source = fh.read()

    tree = ast.parse(source, filename=file_path)
    visitor = CapabilityVisitor(file_path=file_path)
    visitor.visit(tree)
    return visitor.findings


def extract_capabilities_from_source(source_code: str, file_path: str = "<string>") -> ASTFindings:
    """
    Parse a Python source string (rather than a file) and extract capability signals.
    Useful for analysing code fetched from a remote registry without writing to disk.

    Parameters
    ----------
    source_code : str
        Raw Python source text.
    file_path : str
        Label to use in findings (default: '<string>').

    Returns
    -------
    ASTFindings
    """
    tree = ast.parse(source_code, filename=file_path)
    visitor = CapabilityVisitor(file_path=file_path)
    visitor.visit(tree)
    return visitor.findings
