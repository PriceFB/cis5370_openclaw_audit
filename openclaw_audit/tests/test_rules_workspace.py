# ---------------------------------------------------------------------------
# tests/test_rules_workspace.py — Unit tests for workspace/isolation rules
# ---------------------------------------------------------------------------
"""Tests for WeakAgentIsolationRule, WorkspacePathRiskRule, BroadFilesystemAccessRule."""

from __future__ import annotations

from pathlib import Path

from openclaw_audit.models import DiscoveredFile, LoadedDocument
from openclaw_audit.rules.workspace_rules import (
    BroadFilesystemAccessRule,
    WeakAgentIsolationRule,
    WorkspacePathRiskRule,
)


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


class TestWeakAgentIsolationRule:
    def test_detects_shared_workspace(self):
        doc = _make_doc("shared_workspace: true\nmount_all: true")
        findings = WeakAgentIsolationRule().apply(doc)
        assert len(findings) > 0

    def test_ignores_isolated(self):
        doc = _make_doc("workspace: /home/agent1/work\nisolated: true")
        findings = WeakAgentIsolationRule().apply(doc)
        assert len(findings) == 0


class TestWorkspacePathRiskRule:
    def test_detects_tmp_workspace(self):
        doc = _make_doc(
            'base_dir: /tmp',
            parsed_data={"base_dir": "/tmp"},
        )
        findings = WorkspacePathRiskRule().apply(doc)
        assert len(findings) > 0

    def test_ignores_safe_path(self):
        doc = _make_doc(
            'workspace: /opt/openclaw/agent1',
            parsed_data={"workspace": "/opt/openclaw/agent1"},
        )
        findings = WorkspacePathRiskRule().apply(doc)
        assert len(findings) == 0


class TestBroadFilesystemAccessRule:
    def test_detects_host_mount(self):
        doc = _make_doc("volumes:\n  - /:/host-root:ro")
        findings = BroadFilesystemAccessRule().apply(doc)
        assert len(findings) > 0

    def test_detects_docker_sock(self):
        doc = _make_doc("volumes:\n  - /var/run/docker.sock:/var/run/docker.sock")
        findings = BroadFilesystemAccessRule().apply(doc)
        assert len(findings) > 0
