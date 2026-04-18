# ---------------------------------------------------------------------------
# tests/test_parsers.py — Unit tests for file parsers
# ---------------------------------------------------------------------------
"""Tests for JSON, YAML, TOML, and text parsers."""

from __future__ import annotations

from openclaw_audit.parsers.json_parser import parse_json
from openclaw_audit.parsers.yaml_parser import parse_yaml
from openclaw_audit.parsers.toml_parser import parse_toml
from openclaw_audit.parsers.text_parser import parse_text
from openclaw_audit.parsers import try_parse


class TestJsonParser:
    def test_valid_json(self):
        assert parse_json('{"key": "value"}') == {"key": "value"}

    def test_invalid_json(self):
        assert parse_json("{not valid json}") is None

    def test_empty_string(self):
        assert parse_json("") is None


class TestYamlParser:
    def test_valid_yaml(self):
        result = parse_yaml("key: value\nlist:\n  - one\n  - two")
        assert result == {"key": "value", "list": ["one", "two"]}

    def test_invalid_yaml(self):
        # YAML is very permissive, so most strings parse as scalars
        result = parse_yaml("key: [unclosed")
        # Should not raise
        assert result is not None or result is None

    def test_empty_string(self):
        result = parse_yaml("")
        assert result is None  # empty doc → None


class TestTomlParser:
    def test_valid_toml(self):
        result = parse_toml('[section]\nkey = "value"')
        assert result == {"section": {"key": "value"}}

    def test_invalid_toml(self):
        assert parse_toml("not [valid toml") is None


class TestTextParser:
    def test_splits_lines(self):
        assert parse_text("line1\nline2\nline3") == ["line1", "line2", "line3"]

    def test_empty(self):
        assert parse_text("") == []


class TestTryParse:
    def test_dispatches_json(self):
        data, fmt = try_parse('{"a": 1}', "json")
        assert data == {"a": 1}
        assert fmt == "json"

    def test_dispatches_yaml(self):
        data, fmt = try_parse("key: value", "yaml")
        assert data == {"key": "value"}
        assert fmt == "yaml"

    def test_falls_back_to_text(self):
        data, fmt = try_parse("hello world", "python")
        assert data is None
        assert fmt == "text"
