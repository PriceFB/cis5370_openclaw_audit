# ---------------------------------------------------------------------------
# rules/node_rules.py — Node and device command-surface rules
#
# OpenClaw may support remote "nodes" — edge devices, cameras, or other
# endpoints that accept commands from the orchestration layer.  These
# rules look for indicators of node registration and device command
# surfaces.
# ---------------------------------------------------------------------------
"""
Rules for detecting node/device registration and command surfaces.
"""

from __future__ import annotations

import re

from openclaw_audit.models import Evidence, Finding, LoadedDocument
from openclaw_audit.rules.base import BaseRule


# ---------------------------------------------------------------------------
# Rule: NODE_COMMAND_SURFACE
# ---------------------------------------------------------------------------
# Purpose:
#     Detect node/device registration, remote command dispatch, or
#     device-control configuration.
# Why this matters:
#     Remote command surfaces let the orchestration layer execute
#     actions on edge devices.  If not properly authenticated and
#     authorised, an attacker could pivot from the orchestration
#     plane to physical/edge infrastructure.
# ---------------------------------------------------------------------------

class NodeCommandSurfaceRule(BaseRule):
    rule_id = "NODE_COMMAND_SURFACE"
    category = "NODE_COMMAND_SURFACE"
    severity = "high"
    description = (
        "Detects node/device registration or remote command-dispatch "
        "configuration that may expand the attack surface to edge "
        "infrastructure."
    )
    recommendation = (
        "Require mutual TLS or strong API-key authentication for node "
        "communication.  Implement per-node command allow-lists."
    )

    _NODE_PATTERN = re.compile(
        r"(node[_-]?(register|config|command|control|list|endpoint|url|host)|"
        r"device[_-]?(register|command|control|list|endpoint)|"
        r"remote[_-]?(command|exec|control|action)|"
        r"edge[_-]?(node|device|agent)|"
        r"camera[_-]?(command|control|stream|url)|"
        r"iot[_-]?(device|command|endpoint))",
        re.IGNORECASE,
    )

    def apply(self, document: LoadedDocument) -> list[Finding]:
        evidence: list[Evidence] = []

        evidence.extend(self._text_scan(document, self._NODE_PATTERN))

        if document.parsed_data is not None:
            for path, value in self._key_search(document.parsed_data, self._NODE_PATTERN):
                evidence.append(
                    Evidence(
                        file_path=document.file.relative_path,
                        matched_text=f"{path} = {value}",
                        context="Node/device config in structured data",
                    )
                )

        if not evidence:
            return []

        return [
            self._make_finding(
                title="Node / device command surface detected",
                description=(
                    "Configuration or code references node registration, "
                    "device commands, or remote control surfaces.  This "
                    "may allow the orchestration layer to execute actions "
                    "on edge infrastructure."
                ),
                evidence=evidence,
                confidence="medium",
                tags=["node", "device", "command"],
            )
        ]
