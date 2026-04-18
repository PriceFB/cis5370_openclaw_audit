# ---------------------------------------------------------------------------
# tests/test_scan_integration.py — End-to-end integration test
#
# Runs the full pipeline against the fixtures directory and verifies
# that findings, risk scores, and output artifacts are produced.
# ---------------------------------------------------------------------------
"""Integration test: full scan of the test fixtures directory."""

from __future__ import annotations

from pathlib import Path

from openclaw_audit.config import ScanConfig
from openclaw_audit.scanner import run_scan


FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestFullScanIntegration:
    def test_scan_produces_findings(self):
        """The fixture directory should trigger multiple rules."""
        config = ScanConfig(target_path=FIXTURES_DIR)
        result = run_scan(config)

        assert result.files_scanned > 0
        assert len(result.findings) > 0

    def test_scan_produces_risk_score(self):
        config = ScanConfig(target_path=FIXTURES_DIR)
        result = run_scan(config)

        assert result.risk_score > 0
        assert result.risk_band in ("Low", "Moderate", "High", "Critical")

    def test_scan_infers_architecture(self):
        config = ScanConfig(target_path=FIXTURES_DIR)
        result = run_scan(config)

        assert len(result.components) > 0

    def test_scan_produces_category_scores(self):
        config = ScanConfig(target_path=FIXTURES_DIR)
        result = run_scan(config)

        assert len(result.category_scores) > 0

    def test_severity_filter(self):
        """Filtering at 'high' should produce fewer findings than 'info'."""
        config_all = ScanConfig(target_path=FIXTURES_DIR, min_severity="info")
        config_high = ScanConfig(target_path=FIXTURES_DIR, min_severity="high")

        result_all = run_scan(config_all)
        result_high = run_scan(config_high)

        assert len(result_all.findings) >= len(result_high.findings)

    def test_handles_malformed_files(self):
        """The scanner should not crash on malformed JSON."""
        config = ScanConfig(target_path=FIXTURES_DIR)
        result = run_scan(config)
        # If we get here without an exception, the test passes
        assert result is not None

    def test_expected_categories_present(self):
        """At least some of the core categories should fire on fixtures."""
        config = ScanConfig(target_path=FIXTURES_DIR)
        result = run_scan(config)

        categories = {f.category for f in result.findings}
        expected_subset = {
            "NON_LOCALHOST_BIND",
            "TOKEN_STORAGE_RISK",
            "EXECUTION_SURFACE",
        }
        assert expected_subset.issubset(categories), (
            f"Missing categories: {expected_subset - categories}"
        )
