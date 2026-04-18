# ---------------------------------------------------------------------------
# utils/patterns.py — Shared regex and string-matching helpers
#
# Centralises commonly reused patterns so that individual rules don't
# each re-invent the same regexes.
# ---------------------------------------------------------------------------
"""Reusable regex patterns for security-relevant string detection."""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Network / bind patterns
# ---------------------------------------------------------------------------

# Matches IPv4 addresses that are NOT localhost (127.x.x.x)
NON_LOCALHOST_IPV4 = re.compile(
    r"\b(?!127\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
)

# Matches the IPv4 wildcard bind address
WILDCARD_BIND = re.compile(r"\b0\.0\.0\.0\b")

# Matches IPv6 wildcard (::)
IPV6_WILDCARD = re.compile(r"(?<![:\w])::(?![:\w])")

# ---------------------------------------------------------------------------
# Secret / token patterns
# ---------------------------------------------------------------------------

# Common secret-ish key names (case-insensitive flag applied at call site)
SECRET_KEY_NAMES = re.compile(
    r"(api[_-]?key|secret|token|password|passwd|auth[_-]?token|"
    r"access[_-]?key|private[_-]?key|credentials?|bearer)",
    re.IGNORECASE,
)

# Looks like a high-entropy hex or base64 value (at least 16 chars)
HIGH_ENTROPY_VALUE = re.compile(r"[A-Za-z0-9+/=_-]{16,}")

# ---------------------------------------------------------------------------
# Execution / command patterns
# ---------------------------------------------------------------------------

EXEC_KEYWORDS = re.compile(
    r"\b(exec|execute|run_command|subprocess|shell|eval|spawn|popen)\b",
    re.IGNORECASE,
)

DYNAMIC_IMPORT = re.compile(
    r"\b(importlib|__import__|require\(|dynamic\s+import|load_module)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Path / filesystem patterns
# ---------------------------------------------------------------------------

BROAD_PATH = re.compile(
    r'["\']?\s*/\s*["\']?'   # bare "/" root reference
    r"|"
    r"\.\./",                  # parent-directory traversal
)

HOST_MOUNT = re.compile(
    r"(volumes|mounts|host_path|hostPath)\s*:",
    re.IGNORECASE,
)
