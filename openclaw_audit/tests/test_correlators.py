# ---------------------------------------------------------------------------
# tests/test_correlators.py — Unit tests for correlation logic
# ---------------------------------------------------------------------------
"""Tests for correlate_findings and infer_architecture."""

from __future__ import annotations

from openclaw_audit.models import Evidence, Finding
from openclaw_audit.correlators import correlate_findings, infer_architecture


def _finding(category: str, severity: str = "high") -> Finding:
    return Finding(
        id=f"test-{category}",
        category=category,
        severity=severity,
        confidence="medium",
        title=f"Test {category}",
        description="Testing.",
        recommendation="Fix.",
        evidence=[Evidence(file_path="test.yaml", line_number=1, matched_text="test")],
    )


class TestCorrelateFndings:
    def test_admin_correlation(self):
        """Network bind + admin surface should produce correlated finding."""
        raw = [
            _finding("NON_LOCALHOST_BIND"),
            _finding("EXPOSED_ADMIN_SURFACE"),
        ]
        result = correlate_findings(raw)
        correlated = [f for f in result if f.id.startswith("CORR-")]
        assert len(correlated) >= 1

    def test_plugin_correlation(self):
        """Plugin risk + execution surface should correlate."""
        raw = [
            _finding("PLUGIN_TRUST_RISK"),
            _finding("EXECUTION_SURFACE"),
        ]
        result = correlate_findings(raw)
        correlated = [f for f in result if f.id.startswith("CORR-")]
        assert len(correlated) >= 1

    def test_no_false_correlation(self):
        """Unrelated categories should not produce correlated findings."""
        raw = [_finding("TOKEN_STORAGE_RISK")]
        result = correlate_findings(raw)
        correlated = [f for f in result if f.id.startswith("CORR-")]
        assert len(correlated) == 0


class TestInferArchitecture:
    def test_produces_components(self):
        findings = [
            _finding("NON_LOCALHOST_BIND"),
            _finding("PLUGIN_TRUST_RISK"),
            _finding("NODE_COMMAND_SURFACE"),
        ]
        components, edges = infer_architecture(findings)
        names = {c.name for c in components}
        assert "Gateway" in names
        assert "Plugins / Skills" in names
        assert "Nodes / Devices" in names

    def test_empty_findings(self):
        components, edges = infer_architecture([])
        assert len(components) == 0
        assert len(edges) == 0
