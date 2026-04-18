# ---------------------------------------------------------------------------
# rules/auth_rules.py — API and admin surface exposure rules
#
# These rules detect configurations that may expose HTTP APIs, admin
# dashboards, or other privileged interfaces to a wider audience than
# intended.
# ---------------------------------------------------------------------------
"""
Rules for detecting publicly exposed API endpoints and admin surfaces.
"""

from __future__ import annotations

import re

from openclaw_audit.models import Evidence, Finding, LoadedDocument
from openclaw_audit.rules.base import BaseRule


# ---------------------------------------------------------------------------
# Rule: API_EXPOSURE
# ---------------------------------------------------------------------------
# Purpose:
#     Detect HTTP API or REST endpoint configuration that suggests an
#     interface is exposed — especially if combined with broad bind
#     settings.
# Why this matters:
#     Exposed APIs may allow unauthenticated access to orchestration
#     actions, agent management, or data retrieval endpoints.
# ---------------------------------------------------------------------------

class ApiExposureRule(BaseRule):
    rule_id = "API_EXPOSURE"
    category = "API_EXPOSURE"
    severity = "medium"
    description = (
        "Detects HTTP API, REST endpoint, or web-server configuration "
        "that may expose orchestration interfaces."
    )
    recommendation = (
        "Restrict API listeners to localhost or authenticated-only access. "
        "Use API keys, OAuth, or mutual TLS for external-facing endpoints."
    )

    _API_PATTERN = re.compile(
        r"(api[_-]?(server|listen|port|host|endpoint|url|base)|"
        r"rest[_-]?(server|port|listen)|http[_-]?(server|listen|port)|"
        r"web[_-]?(server|port|listen)|server[_-]?(port|host|listen)|"
        r"graphql[_-]?(endpoint|port)|grpc[_-]?(port|listen))",
        re.IGNORECASE,
    )

    _PORT_NUMBER = re.compile(r"\b\d{2,5}\b")

    def apply(self, document: LoadedDocument) -> list[Finding]:
        evidence: list[Evidence] = []

        # Text scan
        evidence.extend(self._text_scan(document, self._API_PATTERN))

        # Structured key search
        if document.parsed_data is not None:
            for path, value in self._key_search(document.parsed_data, self._API_PATTERN):
                evidence.append(
                    Evidence(
                        file_path=document.file.relative_path,
                        matched_text=f"{path} = {value}",
                        context="API configuration in structured data",
                    )
                )

        if not evidence:
            return []

        return [
            self._make_finding(
                title="API / HTTP endpoint configuration detected",
                description=(
                    "Configuration keys suggest an HTTP or API server is defined. "
                    "If publicly reachable, this may allow unauthenticated access "
                    "to orchestration features."
                ),
                evidence=evidence,
                confidence="medium",
                tags=["api", "network"],
            )
        ]


# ---------------------------------------------------------------------------
# Rule: EXPOSED_ADMIN_SURFACE
# ---------------------------------------------------------------------------
# Purpose:
#     Detect dashboard, admin panel, or management UI configuration.
# Why this matters:
#     Admin interfaces often have full control over agents, tools,
#     workspaces, and secrets.  Exposing them without strong auth
#     is a critical risk.
# ---------------------------------------------------------------------------

class ExposedAdminSurfaceRule(BaseRule):
    rule_id = "EXPOSED_ADMIN_SURFACE"
    category = "EXPOSED_ADMIN_SURFACE"
    severity = "high"
    description = (
        "Detects configuration of admin dashboards or management UIs "
        "that may be accessible beyond localhost."
    )
    recommendation = (
        "Restrict admin interfaces to localhost.  Require strong "
        "authentication and consider placing behind a VPN or bastion."
    )

    _ADMIN_PATTERN = re.compile(
        r"(dashboard|admin[_-]?(panel|ui|port|host|listen|url)|"
        r"management[_-]?(ui|port|console)|control[_-]?(panel|plane)|"
        r"web[_-]?ui|console[_-]?(port|listen|host))",
        re.IGNORECASE,
    )

    def apply(self, document: LoadedDocument) -> list[Finding]:
        evidence: list[Evidence] = []

        evidence.extend(self._text_scan(document, self._ADMIN_PATTERN))

        if document.parsed_data is not None:
            for path, value in self._key_search(document.parsed_data, self._ADMIN_PATTERN):
                evidence.append(
                    Evidence(
                        file_path=document.file.relative_path,
                        matched_text=f"{path} = {value}",
                        context="Admin/dashboard config in structured data",
                    )
                )

        if not evidence:
            return []

        return [
            self._make_finding(
                title="Admin / dashboard surface detected",
                description=(
                    "Configuration references an admin panel, dashboard, or "
                    "management console.  If reachable externally, this could "
                    "give an attacker full control over the orchestration system."
                ),
                evidence=evidence,
                confidence="medium",
                tags=["admin", "dashboard"],
            )
        ]
