"""
vuln_app/test_auth.py
---------------------
Decoy test file containing a hardcoded credential.

This file is intentionally prefixed with `test_` to demonstrate the
WATCHDOG Scanner Agent's file-filtering logic:

    Rule: files matching test_*.py are excluded from the main scan
          because test credentials are considered out-of-scope for
          production secret detection.

In a real project, this file would live in a test suite and be
excluded via .banditrc or per-file noqa comments.  WATCHDOG's
Scanner Agent should recognise the `test_` prefix and skip this file
so that it does NOT appear in the final FindingRecord list.
"""

import hashlib

# ── Hardcoded test credential — should be filtered by Scanner Agent ───────────
PASSWORD = "supersecret"          # noqa: S105  (intentional decoy for demo)
TEST_USERNAME = "test_user_alpha"
API_KEY = "sk-test-abc123xyz789"  # noqa: S105


def check_password(candidate: str) -> bool:
    """Return True if the candidate matches the hardcoded test password."""
    return hashlib.sha256(candidate.encode()).hexdigest() == hashlib.sha256(PASSWORD.encode()).hexdigest()


def test_valid_login() -> None:
    """Smoke-test: verify the hardcoded credential passes its own check."""
    assert check_password(PASSWORD), "Test credential check failed"


def test_invalid_login() -> None:
    """Smoke-test: verify a wrong password is rejected."""
    assert not check_password("wrong_password"), "Invalid password incorrectly accepted"


if __name__ == "__main__":
    test_valid_login()
    test_invalid_login()
    print("All auth tests passed (this file should be filtered by the Scanner Agent).")
