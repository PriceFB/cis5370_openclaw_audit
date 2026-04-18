# ---------------------------------------------------------------------------
# rules/execution_rules.py — Execution surface and tooling rules
#
# These rules detect broad execution capabilities, unrestricted tooling
# access, and shared agents with elevated privileges — all of which
# increase the blast radius if any single component is compromised.
# ---------------------------------------------------------------------------
"""
Rules for detecting broad execution surfaces and unrestricted tooling.
"""

from __future__ import annotations

import re

from openclaw_audit.models import Evidence, Finding, LoadedDocument
from openclaw_audit.rules.base import BaseRule
from openclaw_audit.utils.patterns import EXEC_KEYWORDS


# ---------------------------------------------------------------------------
# Rule: EXECUTION_SURFACE
# ---------------------------------------------------------------------------
# Purpose:
#     Detect configuration or code that grants broad code-execution
#     capabilities (subprocess, eval, exec, shell commands).
# Why this matters:
#     Execution primitives are the most dangerous capabilities an
#     orchestration system can expose.  A compromised agent with exec
#     access can run arbitrary commands on the host.
# ---------------------------------------------------------------------------

class ExecutionSurfaceRule(BaseRule):
    rule_id = "EXECUTION_SURFACE"
    category = "EXECUTION_SURFACE"
    severity = "critical"
    description = (
        "Detects broad code-execution capabilities such as subprocess, "
        "eval, exec, or shell command access."
    )
    recommendation = (
        "Restrict execution to a vetted allow-list of commands.  Run "
        "exec-capable agents in hardened, resource-limited containers."
    )

    def apply(self, document: LoadedDocument) -> list[Finding]:
        evidence = self._text_scan(document, EXEC_KEYWORDS)

        if not evidence:
            return []

        return [
            self._make_finding(
                title="Broad execution surface detected",
                description=(
                    "Code or configuration references execution primitives "
                    "(subprocess, eval, exec, shell).  If agents can invoke "
                    "these, the blast radius of a compromise is severe."
                ),
                evidence=evidence,
                confidence="medium",
                tags=["execution", "command"],
            )
        ]


# ---------------------------------------------------------------------------
# Rule: UNRESTRICTED_TOOLING
# ---------------------------------------------------------------------------
# Purpose:
#     Detect tool-access configurations that grant agents a wide or
#     unrestricted set of tools without explicit approval gates.
# Why this matters:
#     Many orchestration frameworks use "tools" to let agents interact
#     with the environment (browse the web, read files, send emails).
#     Without per-tool approval, a rogue agent can abuse the entire
#     tool surface.
# ---------------------------------------------------------------------------

class UnrestrictedToolingRule(BaseRule):
    rule_id = "UNRESTRICTED_TOOLING"
    category = "UNRESTRICTED_TOOLING"
    severity = "high"
    description = (
        "Detects tool-access configuration that grants agents a wide "
        "or unrestricted set of capabilities without approval gates."
    )
    recommendation = (
        "Implement per-tool approval policies.  Use role-based access "
        "control to restrict which agents can invoke which tools."
    )

    _TOOL_PATTERN = re.compile(
        r"(tool[_-]?(access|list|all|enabled|allow|grant|permission)|"
        r"allowed[_-]?tools|"
        r"tool[_-]?approval|"
        r"unrestricted[_-]?tool|"
        r"auto[_-]?approve[_-]?tool|"
        r"tool[_-]?whitelist|"
        r"capabilities?\s*:\s*\[?\s*\*)",
        re.IGNORECASE,
    )

    def apply(self, document: LoadedDocument) -> list[Finding]:
        evidence: list[Evidence] = []

        evidence.extend(self._text_scan(document, self._TOOL_PATTERN))

        if document.parsed_data is not None:
            for path, value in self._key_search(document.parsed_data, self._TOOL_PATTERN):
                evidence.append(
                    Evidence(
                        file_path=document.file.relative_path,
                        matched_text=f"{path} = {value}",
                        context="Unrestricted tool config in structured data",
                    )
                )

        if not evidence:
            return []

        return [
            self._make_finding(
                title="Unrestricted tool access for agents",
                description=(
                    "Configuration suggests agents have broad or auto-approved "
                    "access to tools.  Without approval gates, any compromised "
                    "agent can abuse the full tool surface."
                ),
                evidence=evidence,
                confidence="medium",
                tags=["tooling", "agent"],
            )
        ]


# ---------------------------------------------------------------------------
# Rule: SHARED_AGENT_HIGH_PRIV
# ---------------------------------------------------------------------------
# Purpose:
#     Detect configurations where agents are shared across tenants or
#     contexts AND have elevated privileges (exec, browser, filesystem).
# Why this matters:
#     A shared agent with high privileges is a single point of compromise
#     that can affect multiple users or workspaces.
# ---------------------------------------------------------------------------

class SharedAgentHighPrivRule(BaseRule):
    rule_id = "SHARED_AGENT_HIGH_PRIV"
    category = "SHARED_AGENT_HIGH_PRIV"
    severity = "critical"
    description = (
        "Detects shared agents with elevated privileges (exec, browser, "
        "filesystem access) that may serve as a cross-tenant pivot."
    )
    recommendation = (
        "Avoid sharing privileged agents across tenants.  Use per-tenant "
        "agent instances with the minimum required capabilities."
    )

    _SHARED_AGENT = re.compile(
        r"(shared[_-]?agent|global[_-]?agent|common[_-]?agent|"
        r"multi[_-]?tenant[_-]?agent|agent[_-]?sharing|"
        r"reuse[_-]?agent)",
        re.IGNORECASE,
    )

    _HIGH_PRIV = re.compile(
        r"(exec|execute|browser|filesystem|shell|root|admin|sudo|"
        r"privileged|elevated|unrestricted)",
        re.IGNORECASE,
    )

    def apply(self, document: LoadedDocument) -> list[Finding]:
        # Require BOTH a shared-agent signal AND a high-privilege signal
        shared_hits = self._text_scan(document, self._SHARED_AGENT)
        priv_hits = self._text_scan(document, self._HIGH_PRIV)

        if not shared_hits and not priv_hits:
            return []

        # If we see both in the same file, confidence is higher
        if shared_hits and priv_hits:
            return [
                self._make_finding(
                    title="Shared agent with elevated privileges",
                    description=(
                        "This file references shared/global agents AND "
                        "elevated capabilities (exec, browser, filesystem).  "
                        "A shared privileged agent is a high-value target."
                    ),
                    evidence=shared_hits + priv_hits,
                    confidence="high",
                    tags=["agent", "privilege", "shared"],
                )
            ]

        # If only shared-agent signals are present, still flag at lower confidence
        if shared_hits:
            return [
                self._make_finding(
                    title="Shared agent detected (review privileges)",
                    description=(
                        "Configuration references shared or global agents.  "
                        "Verify that these agents do not carry elevated "
                        "privileges that could span tenant boundaries."
                    ),
                    evidence=shared_hits,
                    confidence="low",
                    tags=["agent", "shared"],
                )
            ]

        return []
