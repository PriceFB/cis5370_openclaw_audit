# ---------------------------------------------------------------------------
# parsers/ — Structured-file parsers with graceful fallback
#
# Each sub-module attempts to parse a specific format.  The top-level
# ``try_parse()`` function dispatches to the right parser based on the
# file type string assigned during discovery.
# ---------------------------------------------------------------------------
"""
Parser dispatch for JSON, YAML, TOML, and plain text.
"""

from __future__ import annotations

from typing import Any

from openclaw_audit.parsers.json_parser import parse_json
from openclaw_audit.parsers.yaml_parser import parse_yaml
from openclaw_audit.parsers.toml_parser import parse_toml


def try_parse(raw_text: str, file_type: str) -> tuple[Any | None, str]:
    """
    Attempt to parse *raw_text* as the structured format implied by
    *file_type*.

    Returns ``(parsed_data, format_name)``.  On failure the parsed_data
    is ``None`` and format_name falls back to ``"text"``.
    """
    if file_type == "json":
        data = parse_json(raw_text)
        if data is not None:
            return data, "json"

    elif file_type in ("yaml", "yml"):
        data = parse_yaml(raw_text)
        if data is not None:
            return data, "yaml"

    elif file_type == "toml":
        data = parse_toml(raw_text)
        if data is not None:
            return data, "toml"

    # For all other file types (or when parsing fails) we keep the raw text.
    return None, "text"
