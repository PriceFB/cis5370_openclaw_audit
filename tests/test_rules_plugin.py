# ---------------------------------------------------------------------------
# tests/test_rules_plugin.py — Unit tests for plugin trust rules
# ---------------------------------------------------------------------------
"""Tests for PluginTrustRiskRule."""

from __future__ import annotations

from pathlib import Path

from openclaw_audit.models import DiscoveredFile, LoadedDocument
from openclaw_audit.rules.plugin_rules import PluginTrustRiskRule


def _make_doc(text: str, file_type: str = "yaml", parsed_data=None) -> LoadedDocument:
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


class TestPluginTrustRiskRule:
    def test_detects_plugin_dir(self):
        doc = _make_doc("plugin_dir: /opt/plugins\nextension_load: dynamic")
        findings = PluginTrustRiskRule().apply(doc)
        assert len(findings) > 0

    def test_detects_importlib(self):
        doc = _make_doc(
            "import importlib\nmod = importlib.import_module(name)",
            file_type="python",
        )
        findings = PluginTrustRiskRule().apply(doc)
        assert len(findings) > 0

    def test_detects_structured_plugin_config(self):
        doc = _make_doc(
            "plugin_dir: /plugins",
            parsed_data={"plugin_dir": "/opt/openclaw/plugins", "auto_load": True},
        )
        findings = PluginTrustRiskRule().apply(doc)
        assert len(findings) > 0

    def test_ignores_unrelated(self):
        doc = _make_doc("log_level: debug\nworkers: 4")
        findings = PluginTrustRiskRule().apply(doc)
        assert len(findings) == 0
