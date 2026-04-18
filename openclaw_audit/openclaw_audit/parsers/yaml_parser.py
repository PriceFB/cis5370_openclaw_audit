# ---------------------------------------------------------------------------
# yaml_parser.py — Best-effort YAML parsing
# ---------------------------------------------------------------------------
"""Parse a string as YAML, returning ``None`` on failure."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def parse_yaml(raw_text: str) -> Any | None:
    """
    Attempt to parse *raw_text* as YAML using the safe loader.

    Returns the parsed object on success, or ``None`` on any error.
    This function never raises.
    """
    try:
        import yaml
        return yaml.safe_load(raw_text)
    except Exception as exc:  # noqa: BLE001 — intentionally broad
        logger.debug("YAML parse failed: %s", exc)
        return None
