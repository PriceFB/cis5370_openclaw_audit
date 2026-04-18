# ---------------------------------------------------------------------------
# tests/test_rules_auth.py — Unit tests for API/admin exposure rules
# ---------------------------------------------------------------------------
"""Tests for ApiExposureRule and ExposedAdminSurfaceRule."""

from __future__ import annotations

from pathlib import Path

from openclaw_audit.models import DiscoveredFile, LoadedDocument
from openclaw_audit.rules.auth_rules import ApiExposureRule, ExposedAdminSurfaceRule


def _make_doc(text: str, parsed_data=None) -> LoadedDocument:
    return LoadedDocument(
        file=DiscoveredFile(
            path=Path("/fake/config.json"),
            relative_path="config.json",
            file_type="json",
            size_bytes=len(text),
        ),
        raw_text=text,
        lines=text.splitlines(),
        parsed_data=parsed_data,
        parse_format="json" if parsed_data else "text",
    )


class TestApiExposureRule:
    def test_detects_api_server_port(self):
        doc = _make_doc('{"api_server_port": 3000}', parsed_data={"api_server_port": 3000})
        findings = ApiExposureRule().apply(doc)
        assert len(findings) > 0

    def test_detects_http_listen(self):
        doc = _make_doc("http_server_listen: 0.0.0.0:8080")
        findings = ApiExposureRule().apply(doc)
        assert len(findings) > 0

    def test_ignores_unrelated(self):
        doc = _make_doc("database: postgres\nretry: 5")
        findings = ApiExposureRule().apply(doc)
        assert len(findings) == 0


class TestExposedAdminSurfaceRule:
    def test_detects_dashboard(self):
        doc = _make_doc("dashboard_port: 9090\nadmin_panel_host: 0.0.0.0")
        findings = ExposedAdminSurfaceRule().apply(doc)
        assert len(findings) > 0

    def test_detects_dashboard_in_structured(self):
        doc = _make_doc(
            "dashboard: true",
            parsed_data={"dashboard": {"enabled": True, "admin_ui_port": 9090}},
        )
        findings = ExposedAdminSurfaceRule().apply(doc)
        assert len(findings) > 0

    def test_ignores_non_admin(self):
        doc = _make_doc("worker_count: 4\nlog_level: info")
        findings = ExposedAdminSurfaceRule().apply(doc)
        assert len(findings) == 0
