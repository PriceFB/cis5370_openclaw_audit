# ---------------------------------------------------------------------------
# toml_parser.py — Best-effort TOML parsing (Python 3.11+ stdlib)
# ---------------------------------------------------------------------------
"""Parse a string as TOML, returning ``None`` on failure."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def parse_toml(raw_text: str) -> Any | None:
    """
    Attempt to parse *raw_text* as TOML.

    Uses the standard-library ``tomllib`` (Python 3.11+).  Falls back
    to ``None`` on any error.
    """
    try:
        import tomllib
        return tomllib.loads(raw_text)
    except Exception as exc:  # noqa: BLE001
        logger.debug("TOML parse failed: %s", exc)
        return None
