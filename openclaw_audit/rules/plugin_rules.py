# ---------------------------------------------------------------------------
# rules/plugin_rules.py — Plugin and extension trust rules
#
# Orchestration frameworks often support dynamic plugins or "skills".
# These rules look for indicators of plugin loading, extension
# registration, or dynamic code import that may allow untrusted code
# to run inside the orchestration process.
# ---------------------------------------------------------------------------
"""
Rules for detecting risky plugin / extension loading patterns.
"""

from __future__ import annotations

import re

from openclaw_audit.models import Evidence, Finding, LoadedDocument
from openclaw_audit.rules.base import BaseRule
from openclaw_audit.utils.patterns import DYNAMIC_IMPORT


# ---------------------------------------------------------------------------
# Rule: PLUGIN_TRUST_RISK
# ---------------------------------------------------------------------------
# Purpose:
#     Detect plugin directories, dynamic loading mechanisms, or
#     extension registration patterns that may allow untrusted code
#     execution inside the host process.
# Why this matters:
#     Plugins that run in-process without sandboxing inherit the full
#     privileges of the host.  A malicious or compromised plugin can
#     access secrets, modify agents, or pivot to other components.
# ---------------------------------------------------------------------------

class PluginTrustRiskRule(BaseRule):
    rule_id = "PLUGIN_TRUST_RISK"
    category = "PLUGIN_TRUST_RISK"
    severity = "high"
    description = (
        "Detects plugin directories, dynamic code loading, or extension "
        "registration that may allow untrusted code execution."
    )
    recommendation = (
        "Run plugins in isolated sandboxes or containers.  Validate plugin "
        "signatures.  Restrict plugin filesystem and network access."
    )

    _PLUGIN_PATTERN = re.compile(
        r"(plugin[_-]?(dir|path|folder|load|register|enabled|list)|"
        r"extension[_-]?(dir|path|load|register)|"
        r"skill[_-]?(dir|path|load|register|folder)|"
        r"addon[_-]?(dir|path|load)|"
        r"custom[_-]?(tool|action)[_-]?(dir|path))",
        re.IGNORECASE,
    )

    def apply(self, document: LoadedDocument) -> list[Finding]:
        evidence: list[Evidence] = []

        # Text-level scan for plugin-related settings
        evidence.extend(self._text_scan(document, self._PLUGIN_PATTERN))

        # Text-level scan for dynamic import patterns
        evidence.extend(self._text_scan(document, DYNAMIC_IMPORT))

        # Structured-data scan
        if document.parsed_data is not None:
            for path, value in self._key_search(document.parsed_data, self._PLUGIN_PATTERN):
                evidence.append(
                    Evidence(
                        file_path=document.file.relative_path,
                        matched_text=f"{path} = {value}",
                        context="Plugin/extension config in structured data",
                    )
                )

        if not evidence:
            return []

        return [
            self._make_finding(
                title="Plugin / extension loading risk",
                description=(
                    "Configuration or code references plugin loading, extension "
                    "registration, or dynamic imports.  Without sandboxing, "
                    "plugins inherit the full privileges of the host process."
                ),
                evidence=evidence,
                confidence="medium",
                tags=["plugin", "extension", "trust"],
            )
        ]
