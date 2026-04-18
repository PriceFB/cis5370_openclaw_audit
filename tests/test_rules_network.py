# ---------------------------------------------------------------------------
# tests/test_rules_network.py — Unit tests for network-related rules
# ---------------------------------------------------------------------------
"""Tests for NonLocalhostBindRule and TrustedProxyRule."""

from __future__ import annotations

from pathlib import Path

from openclaw_audit.models import DiscoveredFile, LoadedDocument
from openclaw_audit.rules.network_rules import NonLocalhostBindRule, TrustedProxyRule


def _make_doc(text: str, file_type: str = "yaml", parsed_data=None) -> LoadedDocument:
    """Helper: build a LoadedDocument from raw text."""
    return LoadedDocument(
        file=DiscoveredFile(
            path=Path("/fake/config.yaml"),
            relative_path="config.yaml",
            file_type=file_type,
            size_bytes=len(text),
        ),
        raw_text=text,
        lines=text.splitlines(),
        parsed_data=parsed_data,
        parse_format="yaml" if parsed_data else "text",
    )


class TestNonLocalhostBindRule:
    def test_detects_wildcard_bind(self):
        doc = _make_doc("bind_address: 0.0.0.0\nport: 8080")
        rule = NonLocalhostBindRule()
        findings = rule.apply(doc)
        assert len(findings) > 0
        assert any("0.0.0.0" in str(f.evidence) for f in findings)

    def test_detects_wildcard_in_structured_data(self):
        doc = _make_doc(
            "bind_address: 0.0.0.0",
            parsed_data={"bind_address": "0.0.0.0", "port": 8080},
        )
        rule = NonLocalhostBindRule()
        findings = rule.apply(doc)
        assert len(findings) > 0

    def test_ignores_localhost(self):
        doc = _make_doc("bind_address: 127.0.0.1\nport: 8080")
        rule = NonLocalhostBindRule()
        findings = rule.apply(doc)
        assert len(findings) == 0

    def test_detects_ipv6_wildcard(self):
        doc = _make_doc("listen_address: ::\nport: 443")
        rule = NonLocalhostBindRule()
        findings = rule.apply(doc)
        assert len(findings) > 0


class TestTrustedProxyRule:
    def test_detects_trusted_proxy_text(self):
        doc = _make_doc("trusted_proxy: true\nuse_forwarded_headers: yes")
        rule = TrustedProxyRule()
        findings = rule.apply(doc)
        assert len(findings) > 0

    def test_detects_trusted_proxy_structured(self):
        doc = _make_doc(
            "trusted_proxy: true",
            parsed_data={"trusted_proxy": True},
        )
        rule = TrustedProxyRule()
        findings = rule.apply(doc)
        assert len(findings) > 0

    def test_ignores_unrelated_text(self):
        doc = _make_doc("database_host: localhost\nretry: 3")
        rule = TrustedProxyRule()
        findings = rule.apply(doc)
        assert len(findings) == 0
