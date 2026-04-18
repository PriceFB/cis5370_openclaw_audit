# ---------------------------------------------------------------------------
# utils/logging.py — Logging configuration
# ---------------------------------------------------------------------------
"""
One-call logging setup for the CLI.

Verbose mode lowers the threshold to DEBUG; normal mode stays at WARNING
so that only genuinely important messages appear alongside the Rich output.
"""

from __future__ import annotations

import logging
import sys


def configure_logging(*, verbose: bool = False) -> None:
    """Configure the root ``openclaw_audit`` logger."""
    level = logging.DEBUG if verbose else logging.WARNING

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter("[%(levelname)s] %(name)s: %(message)s")
    )

    root = logging.getLogger("openclaw_audit")
    root.setLevel(level)
    root.addHandler(handler)
