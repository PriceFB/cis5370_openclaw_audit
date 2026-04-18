# ---------------------------------------------------------------------------
# rules/network_rules.py — Network-exposure detection rules
#
# These rules look for configuration signals that suggest OpenClaw
# components are binding to non-localhost addresses or enabling trust
# models that weaken perimeter security.
# ---------------------------------------------------------------------------
"""
Rules for detecting risky network bind addresses and proxy trust settings.
"""

from __future__ import annotations

import re

from openclaw_audit.models import Evidence, Finding, LoadedDocument
from openclaw_audit.rules.base import BaseRule
from openclaw_audit.utils.patterns import WILDCARD_BIND, IPV6_WILDCARD


# ---------------------------------------------------------------------------
# Rule: NON_LOCALHOST_BIND
# ---------------------------------------------------------------------------
# Purpose:
#     Detect services configured to listen on 0.0.0.0, ::, or other
#     non-loopback addresses.
# Why this matters:
#     Binding to a wildcard or public address makes the service reachable
#     from any network interface, vastly expanding the attack surface —
#     especially for admin/API endpoints that were likely intended for
#     local use only.
# ---------------------------------------------------------------------------

class NonLocalhostBindRule(BaseRule):
    rule_id = "NON_LOCALHOST_BIND"
    category = "NON_LOCALHOST_BIND"
    severity = "high"
    description = (
        "Detects services configured to bind to 0.0.0.0, ::, or other "
        "non-loopback addresses — expanding network exposure."
    )
    recommendation = (
        "Bind services to 127.0.0.1 (or ::1) unless external access is "
        "explicitly required and protected by additional controls."
    )

    # Patterns that indicate a "bind"/"host"/"listen" context
    _BIND_CONTEXT = re.compile(
        r"(bind|host|listen|address|addr|interface)\s*[:=]",
        re.IGNORECASE,
    )

    def apply(self, document: LoadedDocument) -> list[Finding]:
        findings: list[Finding] = []

        # Strategy 1: scan structured data for bind-like keys
        if document.parsed_data is not None:
            evidence = self._check_structured(document)
            if evidence:
                findings.append(
                    self._make_finding(
                        title="Non-localhost bind address in structured config",
                        description=(
                            "A configuration key related to network binding "
                            "contains a wildcard or non-loopback address."
                        ),
                        evidence=evidence,
                        confidence="high",
                        tags=["network", "bind"],
                    )
                )

        # Strategy 2: line-by-line text scan
        text_evidence = self._check_text(document)
        if text_evidence:
            findings.append(
                self._make_finding(
                    title="Non-localhost bind address in text/config",
                    description=(
                        "A line referencing a bind/listen/host setting contains "
                        "0.0.0.0 or :: which exposes the service publicly."
                    ),
                    evidence=text_evidence,
                    confidence="medium",
                    tags=["network", "bind"],
                )
            )

        return findings

    # -- Internal helpers --------------------------------------------------

    def _check_structured(self, doc: LoadedDocument) -> list[Evidence]:
        """Look for bind-related keys whose values are wildcard addresses."""
        bind_key = re.compile(r"(bind|host|listen|address|addr)", re.IGNORECASE)
        hits = self._key_search(doc.parsed_data, bind_key)

        evidence: list[Evidence] = []
        for path, value in hits:
            val_str = str(value)
            if WILDCARD_BIND.search(val_str) or IPV6_WILDCARD.search(val_str):
                evidence.append(
                    Evidence(
                        file_path=doc.file.relative_path,
                        matched_text=f"{path} = {val_str}",
                        context="Parsed structured config",
                    )
                )
        return evidence

    def _check_text(self, doc: LoadedDocument) -> list[Evidence]:
        """Line-by-line scan for wildcard addresses in a bind context."""
        evidence: list[Evidence] = []
        for idx, line in enumerate(doc.lines, start=1):
            if not self._BIND_CONTEXT.search(line):
                continue
            if WILDCARD_BIND.search(line) or IPV6_WILDCARD.search(line):
                evidence.append(
                    Evidence(
                        file_path=doc.file.relative_path,
                        line_number=idx,
                        matched_text=line.strip(),
                    )
                )
        return evidence


# ---------------------------------------------------------------------------
# Rule: TRUSTED_PROXY_ENABLED
# ---------------------------------------------------------------------------
# Purpose:
#     Detect trusted-proxy or forwarded-header trust settings.
# Why this matters:
#     When a service blindly trusts X-Forwarded-For or similar headers,
#     an attacker can spoof their source IP, bypass IP-based ACLs, or
#     impersonate internal clients.
# ---------------------------------------------------------------------------

class TrustedProxyRule(BaseRule):
    rule_id = "TRUSTED_PROXY_ENABLED"
    category = "TRUSTED_PROXY_ENABLED"
    severity = "medium"
    description = (
        "Detects configurations enabling trusted-proxy or forwarded-header "
        "trust, which may allow IP spoofing."
    )
    recommendation = (
        "Only enable trusted-proxy mode when behind a verified reverse proxy. "
        "Restrict trusted proxy IPs to the minimum set."
    )

    _PROXY_PATTERN = re.compile(
        r"(trusted[_-]?proxy|trust[_-]?proxy|forwarded|x[_-]forwarded|"
        r"proxy[_-]?trust|use[_-]?forwarded[_-]?headers)",
        re.IGNORECASE,
    )

    def apply(self, document: LoadedDocument) -> list[Finding]:
        evidence = self._text_scan(document, self._PROXY_PATTERN)

        if document.parsed_data is not None:
            for path, value in self._key_search(document.parsed_data, self._PROXY_PATTERN):
                if value in (True, "true", "yes", 1, "1"):
                    evidence.append(
                        Evidence(
                            file_path=document.file.relative_path,
                            matched_text=f"{path} = {value}",
                            context="Trusted-proxy enabled in structured config",
                        )
                    )

        if not evidence:
            return []

        return [
            self._make_finding(
                title="Trusted proxy / forwarded-header trust detected",
                description=(
                    "The configuration enables trust for proxy-forwarded headers. "
                    "If the service is not behind a properly-configured reverse "
                    "proxy, this may allow IP spoofing."
                ),
                evidence=evidence,
                confidence="medium",
                tags=["network", "proxy"],
            )
        ]
