# ---------------------------------------------------------------------------
# tests/test_risk.py — Unit tests for the risk scoring engine
# ---------------------------------------------------------------------------
"""Tests for compute_risk."""

from __future__ import annotations

from openclaw_audit.models import Finding
from openclaw_audit.risk import compute_risk


def _finding(severity: str = "medium", confidence: str = "medium", category: str = "TEST") -> Finding:
    return Finding(
        id="test-001",
        category=category,
        severity=severity,
        confidence=confidence,
        title="Test finding",
        description="For testing.",
        recommendation="Fix it.",
    )


class TestComputeRisk:
    def test_empty_findings(self):
        score, band, cats = compute_risk([])
        assert score == 0
        assert band == "Low"
        assert cats == {}

    def test_single_critical(self):
        score, band, cats = compute_risk([_finding("critical", "high")])
        assert score == 15  # 15 * 1.0
        assert band == "Low"  # 15 < 20

    def test_multiple_findings_accumulate(self):
        findings = [_finding("high", "high")] * 5
        score, band, cats = compute_risk(findings)
        assert score == 50  # 5 * 10 * 1.0
        assert band == "High"

    def test_confidence_reduces_score(self):
        f_high = _finding("high", "high")
        f_low = _finding("high", "low")

        score_high, _, _ = compute_risk([f_high])
        score_low, _, _ = compute_risk([f_low])

        assert score_high > score_low

    def test_clamped_to_100(self):
        findings = [_finding("critical", "high")] * 20
        score, band, _ = compute_risk(findings)
        assert score == 100
        assert band == "Critical"

    def test_category_breakdown(self):
        findings = [
            _finding("high", "high", category="A"),
            _finding("medium", "medium", category="B"),
        ]
        _, _, cats = compute_risk(findings)
        assert "A" in cats
        assert "B" in cats
        assert cats["A"] == 10.0   # 10 * 1.0
        assert cats["B"] == 4.5    # 6 * 0.75
