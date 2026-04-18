# ---------------------------------------------------------------------------
# text_parser.py — Fallback text "parser"
#
# This is intentionally trivial: when no structured parser succeeds we
# just return the raw text split into lines.  Having this module makes
# the parser package consistent (every format has a file) and provides
# a natural extension point for future heuristic parsing.
# ---------------------------------------------------------------------------
"""Fallback parser that returns raw text as-is."""

from __future__ import annotations


def parse_text(raw_text: str) -> list[str]:
    """Return the raw text split into lines."""
    return raw_text.splitlines()
