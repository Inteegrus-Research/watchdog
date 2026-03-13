"""
utils/file_utils.py
-------------------
Lightweight file-system utility functions used across the WATCHDOG agent pipeline.

All functions are pure, side-effect-free helpers (except read_file which reads
from disk).  They intentionally have no dependencies outside the standard library
so they can be imported by any agent or utility without circular import risk.
"""

from __future__ import annotations

import os


def file_exists(path: str) -> bool:
    """
    Return True if *path* points to an existing regular file.

    Directories, symlinks to directories, and device files all return False.

    Parameters
    ----------
    path : str
        Filesystem path to check.

    Returns
    -------
    bool
    """
    return os.path.isfile(path)


def read_file(path: str, encoding: str = "utf-8") -> str:
    """
    Read the entire content of a file and return it as a string.

    Parameters
    ----------
    path : str
        Filesystem path to the file.
    encoding : str
        Text encoding (default: 'utf-8').

    Returns
    -------
    str
        File content.

    Raises
    ------
    FileNotFoundError
        If the file does not exist.
    PermissionError
        If the process does not have read access to the file.
    UnicodeDecodeError
        If the file cannot be decoded with the specified encoding.
    """
    if not file_exists(path):
        raise FileNotFoundError(f"File not found: {path}")
    with open(path, "r", encoding=encoding) as fh:
        return fh.read()


def list_python_files(directory: str, recursive: bool = True) -> list[str]:
    """
    Return a sorted list of all *.py file paths within *directory*.

    Parameters
    ----------
    directory : str
        Root directory to search.
    recursive : bool
        If True (default), descend into sub-directories.

    Returns
    -------
    list[str]
        Absolute paths to all discovered Python files.
    """
    py_files: list[str] = []

    if recursive:
        for root, _dirs, files in os.walk(directory):
            for fname in files:
                if fname.endswith(".py"):
                    py_files.append(os.path.join(root, fname))
    else:
        for fname in os.listdir(directory):
            full = os.path.join(directory, fname)
            if fname.endswith(".py") and os.path.isfile(full):
                py_files.append(full)

    return sorted(py_files)


def is_test_file(path: str) -> bool:
    """
    Return True if the filename suggests this is a test file that should
    be excluded from production secret scanning.

    Heuristic: filename starts with ``test_`` or ends with ``_test.py``.

    Parameters
    ----------
    path : str
        Filesystem path (only the basename is inspected).

    Returns
    -------
    bool
    """
    basename = os.path.basename(path)
    return basename.startswith("test_") or basename.endswith("_test.py")


def get_file_extension(path: str) -> str:
    """
    Return the file extension (including the leading dot) in lower case.

    Returns an empty string if the file has no extension.

    Parameters
    ----------
    path : str

    Returns
    -------
    str
        E.g. ``'.py'``, ``'.txt'``, ``''``.
    """
    _, ext = os.path.splitext(path)
    return ext.lower()
