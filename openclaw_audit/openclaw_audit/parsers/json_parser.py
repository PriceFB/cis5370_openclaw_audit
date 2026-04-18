# ---------------------------------------------------------------------------
# json_parser.py — Best-effort JSON parsing
# ---------------------------------------------------------------------------
"""Parse a string as JSON, returning ``None`` on failure."""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def parse_json(raw_text: str) -> Any | None:
    """
    Attempt to parse *raw_text* as JSON.

    Returns the parsed object (dict, list, etc.) on success, or ``None``
    on any parse error.  This function never raises.
    """
    try:
        return json.loads(raw_text)
    except (json.JSONDecodeError, ValueError) as exc:
        logger.debug("JSON parse failed: %s", exc)
        return None
