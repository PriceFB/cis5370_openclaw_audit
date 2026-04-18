# ---------------------------------------------------------------------------
# rules/workspace_rules.py — Workspace and filesystem isolation rules
#
# Orchestration platforms typically give each agent a "workspace" — a
# directory or environment where it operates.  If workspaces overlap,
# use host paths, or have overly broad access, the isolation boundary
# can be bypassed.
# ---------------------------------------------------------------------------
"""
Rules for detecting weak workspace isolation and risky filesystem access.
"""

from __future__ import annotations

import re

from openclaw_audit.models import Evidence, Finding, LoadedDocument
from openclaw_audit.rules.base import BaseRule
from openclaw_audit.utils.patterns import BROAD_PATH, HOST_MOUNT


# ---------------------------------------------------------------------------
# Rule: WEAK_AGENT_ISOLATION
# ---------------------------------------------------------------------------
# Purpose:
#     Detect workspace configuration that suggests agents may share
#     filesystem namespaces or lack container-level isolation.
# Why this matters:
#     Shared workspace directories let one agent read or tamper with
#     another agent's data, tools, or credentials.
# ---------------------------------------------------------------------------

class WeakAgentIsolationRule(BaseRule):
    rule_id = "WEAK_AGENT_ISOLATION"
    category = "WEAK_AGENT_ISOLATION"
    severity = "high"
    description = (
        "Detects shared workspace directories or absence of container/sandbox "
        "isolation between agents."
    )
    recommendation = (
        "Give each agent a dedicated, non-overlapping workspace directory.  "
        "Consider running agents in separate containers with read-only root "
        "filesystems."
    )

    _ISOLATION_PATTERN = re.compile(
        r"(shared[_-]?(workspace|dir|directory|volume)|"
        r"workspace[_-]?sharing|"
        r"common[_-]?(workspace|directory)|"
        r"mount[_-]?(all|shared))",
        re.IGNORECASE,
    )

    def apply(self, document: LoadedDocument) -> list[Finding]:
        evidence: list[Evidence] = []

        evidence.extend(self._text_scan(document, self._ISOLATION_PATTERN))

        if document.parsed_data is not None:
            for path, value in self._key_search(document.parsed_data, self._ISOLATION_PATTERN):
                evidence.append(
                    Evidence(
                        file_path=document.file.relative_path,
                        matched_text=f"{path} = {value}",
                        context="Weak isolation indicator in structured config",
                    )
                )

        if not evidence:
            return []

        return [
            self._make_finding(
                title="Weak agent workspace isolation",
                description=(
                    "Configuration suggests agents may share workspace "
                    "directories or volumes, weakening inter-agent isolation."
                ),
                evidence=evidence,
                confidence="medium",
                tags=["workspace", "isolation"],
            )
        ]


# ---------------------------------------------------------------------------
# Rule: WORKSPACE_PATH_RISK
# ---------------------------------------------------------------------------
# Purpose:
#     Detect workspace or data-directory paths that are unusually broad
#     (e.g. "/", "/tmp", "C:\") or use parent-directory traversal.
# Why this matters:
#     Overly broad workspace paths may expose sensitive host files to
#     agents.
# ---------------------------------------------------------------------------

class WorkspacePathRiskRule(BaseRule):
    rule_id = "WORKSPACE_PATH_RISK"
    category = "WORKSPACE_PATH_RISK"
    severity = "medium"
    description = (
        "Detects workspace or data-directory paths that are overly broad "
        "or use parent-directory traversal."
    )
    recommendation = (
        "Restrict workspace paths to a narrow, dedicated directory.  Avoid "
        "root ('/') or home-directory mounts."
    )

    _WORKSPACE_KEY = re.compile(
        r"(workspace|workdir|work_dir|data_dir|data[_-]?path|"
        r"root[_-]?dir|base[_-]?dir|storage[_-]?path)",
        re.IGNORECASE,
    )

    _RISKY_PATH = re.compile(
        r'(^["\']?/["\']?$|/tmp\b|^\.\./|\\\.\\\.)',
    )

    def apply(self, document: LoadedDocument) -> list[Finding]:
        evidence: list[Evidence] = []

        # Structured: look for workspace-ish keys with risky values
        if document.parsed_data is not None:
            for path, value in self._key_search(document.parsed_data, self._WORKSPACE_KEY):
                if self._RISKY_PATH.search(str(value)):
                    evidence.append(
                        Evidence(
                            file_path=document.file.relative_path,
                            matched_text=f"{path} = {value}",
                            context="Broad workspace path in structured config",
                        )
                    )

        # Text scan: lines that mention workspace AND a risky path
        for idx, line in enumerate(document.lines, start=1):
            if self._WORKSPACE_KEY.search(line) and self._RISKY_PATH.search(line):
                evidence.append(
                    Evidence(
                        file_path=document.file.relative_path,
                        line_number=idx,
                        matched_text=line.strip(),
                    )
                )

        if not evidence:
            return []

        return [
            self._make_finding(
                title="Risky workspace / data-directory path",
                description=(
                    "A workspace or data path appears overly broad (e.g. '/', "
                    "'/tmp', or uses '..').  This may expose sensitive host "
                    "filesystem areas to agents."
                ),
                evidence=evidence,
                confidence="medium",
                tags=["workspace", "path"],
            )
        ]


# ---------------------------------------------------------------------------
# Rule: BROAD_FILESYSTEM_ACCESS
# ---------------------------------------------------------------------------
# Purpose:
#     Detect host-path mounts, volume mappings, or other indicators that
#     agents or plugins can access broad swaths of the host filesystem.
# Why this matters:
#     Host mounts break container isolation and may expose sensitive
#     data, credentials, or system files.
# ---------------------------------------------------------------------------

class BroadFilesystemAccessRule(BaseRule):
    rule_id = "BROAD_FILESYSTEM_ACCESS"
    category = "BROAD_FILESYSTEM_ACCESS"
    severity = "high"
    description = (
        "Detects host-path volume mounts or broad filesystem access "
        "patterns that break container isolation."
    )
    recommendation = (
        "Minimise host-path mounts.  Prefer named volumes with narrow "
        "scope.  Use read-only mounts where possible."
    )

    def apply(self, document: LoadedDocument) -> list[Finding]:
        evidence: list[Evidence] = []

        evidence.extend(self._text_scan(document, HOST_MOUNT))
        evidence.extend(self._text_scan(document, BROAD_PATH))

        if document.parsed_data is not None:
            for path, value in self._key_search(document.parsed_data, HOST_MOUNT):
                evidence.append(
                    Evidence(
                        file_path=document.file.relative_path,
                        matched_text=f"{path} = {value}",
                        context="Host mount in structured config",
                    )
                )

        if not evidence:
            return []

        return [
            self._make_finding(
                title="Broad filesystem / host-mount access",
                description=(
                    "Configuration references host-path mounts or volume "
                    "mappings that may give containers or agents access to "
                    "sensitive host directories."
                ),
                evidence=evidence,
                confidence="low",
                tags=["filesystem", "mount", "isolation"],
            )
        ]
