# ---------------------------------------------------------------------------
# tests/test_rules_secrets.py — Unit tests for secret/token detection rules
# ---------------------------------------------------------------------------
"""Tests for TokenStorageRiskRule and PotentialSecretInConfigRule."""

from __future__ import annotations

from pathlib import Path

from openclaw_audit.models import DiscoveredFile, LoadedDocument
from openclaw_audit.rules.secret_rules import (
    PotentialSecretInConfigRule,
    TokenStorageRiskRule,
)


def _make_doc(text: str, file_type: str = "env", parsed_data=None) -> LoadedDocument:
    return LoadedDocument(
        file=DiscoveredFile(
            path=Path("/fake/.env"),
            relative_path=".env",
            file_type=file_type,
            size_bytes=len(text),
        ),
        raw_text=text,
        lines=text.splitlines(),
        parsed_data=parsed_data,
        parse_format="text",
    )


class TestTokenStorageRiskRule:
    def test_detects_api_key_in_env(self):
        doc = _make_doc("API_KEY=sk-test-1234567890abcdefghijklmnop")
        findings = TokenStorageRiskRule().apply(doc)
        assert len(findings) > 0
        assert findings[0].severity == "critical"

    def test_detects_token_in_structured_json(self):
        doc = _make_doc(
            '{"auth_token": "eyJhbG123456789012345678"}',
            file_type="json",
            parsed_data={"auth_token": "eyJhbG123456789012345678"},
        )
        findings = TokenStorageRiskRule().apply(doc)
        assert len(findings) > 0

    def test_ignores_source_code(self):
        doc = _make_doc(
            'api_key = "test_key_12345678901234567890"',
            file_type="python",
        )
        findings = TokenStorageRiskRule().apply(doc)
        assert len(findings) == 0

    def test_ignores_short_values(self):
        doc = _make_doc("API_KEY=short")
        findings = TokenStorageRiskRule().apply(doc)
        assert len(findings) == 0


class TestPotentialSecretInConfigRule:
    def test_flags_secret_key_in_json(self):
        doc = _make_doc(
            '{"secret": "myvalue"}',
            file_type="json",
            parsed_data={"secret": "myvalue"},
        )
        findings = PotentialSecretInConfigRule().apply(doc)
        assert len(findings) > 0
        assert findings[0].severity == "low"

    def test_ignores_empty_values(self):
        doc = _make_doc(
            '{"api_key": ""}',
            file_type="json",
            parsed_data={"api_key": ""},
        )
        findings = PotentialSecretInConfigRule().apply(doc)
        assert len(findings) == 0
