# ---------------------------------------------------------------------------
# tests/test_rules_node.py — Unit tests for node/device command rules
# ---------------------------------------------------------------------------
"""Tests for NodeCommandSurfaceRule."""

from __future__ import annotations

from pathlib import Path

from openclaw_audit.models import DiscoveredFile, LoadedDocument
from openclaw_audit.rules.node_rules import NodeCommandSurfaceRule


def _make_doc(text: str, file_type: str = "yaml", parsed_data=None) -> LoadedDocument:
    return LoadedDocument(
        file=DiscoveredFile(
            path=Path("/fake/nodes.yaml"),
            relative_path="nodes.yaml",
            file_type=file_type,
            size_bytes=len(text),
        ),
        raw_text=text,
        lines=text.splitlines(),
        parsed_data=parsed_data,
        parse_format="yaml" if parsed_data else "text",
    )


class TestNodeCommandSurfaceRule:
    def test_detects_node_register(self):
        doc = _make_doc("node_register: https://edge.example.com/register")
        findings = NodeCommandSurfaceRule().apply(doc)
        assert len(findings) > 0

    def test_detects_device_command(self):
        doc = _make_doc("device_command_endpoint: /api/v1/devices/command")
        findings = NodeCommandSurfaceRule().apply(doc)
        assert len(findings) > 0

    def test_detects_camera_control(self):
        doc = _make_doc("camera_control: true\ncamera_stream_url: rtsp://cam.local")
        findings = NodeCommandSurfaceRule().apply(doc)
        assert len(findings) > 0

    def test_ignores_unrelated(self):
        doc = _make_doc("database: postgres\nretries: 3")
        findings = NodeCommandSurfaceRule().apply(doc)
        assert len(findings) == 0
