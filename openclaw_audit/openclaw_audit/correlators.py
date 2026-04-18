# ---------------------------------------------------------------------------
# correlators.py — Cross-finding correlation and architecture inference
#
# Individual rules fire in isolation — one rule per document.  The
# correlator looks at the *combined* set of findings to:
#
#   1. Synthesise higher-level findings when multiple low-level signals
#      co-occur (e.g. "wildcard bind + dashboard + token → exposed admin").
#
#   2. Infer an architectural component graph for the Mermaid reporter
#      based on which categories of findings are present.
#
# This "thinking across files" is what makes the tool feel more
# insightful than simple grep.
# ---------------------------------------------------------------------------
"""
Cross-finding correlation and architecture-graph inference.
"""

from __future__ import annotations

import uuid
from collections import defaultdict

from openclaw_audit.models import (
    ArchitectureEdge,
    AttackSurfaceComponent,
    Evidence,
    Finding,
)


# ---------------------------------------------------------------------------
# 1.  Finding correlation
# ---------------------------------------------------------------------------

def correlate_findings(raw_findings: list[Finding]) -> list[Finding]:
    """
    Accept the flat list of per-document findings, apply correlation
    rules, and return the (possibly augmented) list.

    Correlation rules never *remove* findings — they only *add* new
    synthesised findings when multiple signals align.
    """
    augmented = list(raw_findings)

    # Index findings by category for fast lookup
    by_category: dict[str, list[Finding]] = defaultdict(list)
    for f in raw_findings:
        by_category[f.category].append(f)

    # -- Correlation 1: Exposed Admin Surface ------------------------------
    # If we see (non-localhost bind OR API exposure) AND (admin surface OR
    # token risk), synthesise an overarching EXPOSED_ADMIN_SURFACE finding.
    network_signals = by_category.get("NON_LOCALHOST_BIND", []) + by_category.get("API_EXPOSURE", [])
    admin_signals = by_category.get("EXPOSED_ADMIN_SURFACE", []) + by_category.get("TOKEN_STORAGE_RISK", [])

    if network_signals and admin_signals:
        evidence = _collect_evidence(network_signals + admin_signals)
        augmented.append(
            Finding(
                id=f"CORR-ADMIN-{uuid.uuid4().hex[:8]}",
                category="EXPOSED_ADMIN_SURFACE",
                severity="critical",
                confidence="high",
                title="Correlated: publicly exposed admin / API with credential risk",
                description=(
                    "Multiple signals suggest an admin or API surface is "
                    "network-accessible AND credentials may be at risk.  "
                    "This combination greatly increases the likelihood of "
                    "unauthorised administrative access."
                ),
                recommendation=(
                    "Bind admin interfaces to localhost.  Rotate any exposed "
                    "credentials.  Enforce strong authentication."
                ),
                evidence=evidence,
                tags=["correlated", "admin", "network", "credential"],
            )
        )

    # -- Correlation 2: Plugin Trust Risk ----------------------------------
    # If we see plugin-loading signals AND execution-surface signals,
    # the plugin path may lead to arbitrary code execution.
    plugin_signals = by_category.get("PLUGIN_TRUST_RISK", [])
    exec_signals = by_category.get("EXECUTION_SURFACE", [])

    if plugin_signals and exec_signals:
        evidence = _collect_evidence(plugin_signals + exec_signals)
        augmented.append(
            Finding(
                id=f"CORR-PLUGIN-{uuid.uuid4().hex[:8]}",
                category="PLUGIN_TRUST_RISK",
                severity="critical",
                confidence="high",
                title="Correlated: plugin loading with execution primitives",
                description=(
                    "Plugin or extension loading is configured alongside "
                    "execution capabilities (subprocess, eval, shell).  "
                    "A malicious plugin could leverage these to achieve "
                    "arbitrary code execution on the host."
                ),
                recommendation=(
                    "Sandbox plugins in isolated processes or containers.  "
                    "Remove or restrict execution primitives available to "
                    "plugin code."
                ),
                evidence=evidence,
                tags=["correlated", "plugin", "execution"],
            )
        )

    # -- Correlation 3: Shared Agent + Weak Isolation ----------------------
    shared_signals = by_category.get("SHARED_AGENT_HIGH_PRIV", [])
    isolation_signals = (
        by_category.get("WEAK_AGENT_ISOLATION", [])
        + by_category.get("WORKSPACE_PATH_RISK", [])
    )

    if shared_signals and isolation_signals:
        evidence = _collect_evidence(shared_signals + isolation_signals)
        augmented.append(
            Finding(
                id=f"CORR-SHARED-{uuid.uuid4().hex[:8]}",
                category="SHARED_AGENT_HIGH_PRIV",
                severity="critical",
                confidence="high",
                title="Correlated: shared privileged agent with weak isolation",
                description=(
                    "A shared or global agent with elevated privileges is "
                    "combined with weak workspace isolation.  This creates "
                    "a high-risk cross-tenant pivot path."
                ),
                recommendation=(
                    "Dedicate an agent instance per tenant/context.  Enforce "
                    "strict workspace separation with non-overlapping paths."
                ),
                evidence=evidence,
                tags=["correlated", "agent", "isolation"],
            )
        )

    return augmented


# ---------------------------------------------------------------------------
# 2.  Architecture inference
# ---------------------------------------------------------------------------

# Map finding categories to inferred architectural components
_CATEGORY_TO_COMPONENT: dict[str, tuple[str, str]] = {
    "NON_LOCALHOST_BIND":       ("Gateway",          "gateway"),
    "TRUSTED_PROXY_ENABLED":    ("Gateway",          "gateway"),
    "API_EXPOSURE":             ("HTTP API",         "api"),
    "EXPOSED_ADMIN_SURFACE":    ("Dashboard",        "dashboard"),
    "SHARED_AGENT_HIGH_PRIV":   ("Agents",           "agent"),
    "WEAK_AGENT_ISOLATION":     ("Agents",           "agent"),
    "PLUGIN_TRUST_RISK":        ("Plugins / Skills", "plugin"),
    "WORKSPACE_PATH_RISK":      ("Workspaces",       "workspace"),
    "BROAD_FILESYSTEM_ACCESS":  ("Workspaces",       "workspace"),
    "NODE_COMMAND_SURFACE":     ("Nodes / Devices",  "node"),
    "TOKEN_STORAGE_RISK":       ("Secrets Store",    "secret"),
    "POTENTIAL_SECRET_IN_CONFIG": ("Secrets Store",  "secret"),
    "EXECUTION_SURFACE":        ("Agents",           "agent"),
    "UNRESTRICTED_TOOLING":     ("Agents",           "agent"),
}

# Static edges that represent common architectural relationships
_STATIC_EDGES: list[tuple[str, str, str]] = [
    ("External User",   "Gateway",          ""),
    ("HTTP API",        "Gateway",          ""),
    ("Dashboard",       "Gateway",          ""),
    ("Gateway",         "Agents",           ""),
    ("Agents",          "Workspaces",       ""),
    ("Agents",          "Plugins / Skills", ""),
    ("Gateway",         "Nodes / Devices",  ""),
    ("Agents",          "Secrets Store",    "reads"),
]


def infer_architecture(
    findings: list[Finding],
) -> tuple[list[AttackSurfaceComponent], list[ArchitectureEdge]]:
    """
    Build a best-effort architecture graph from the set of findings.

    Returns ``(components, edges)`` where components are the inferred
    nodes and edges are the inferred connections.
    """
    # Determine which component types are evidenced by findings
    seen_types: dict[str, AttackSurfaceComponent] = {}

    for finding in findings:
        mapping = _CATEGORY_TO_COMPONENT.get(finding.category)
        if mapping is None:
            continue
        name, ctype = mapping
        if name not in seen_types:
            seen_types[name] = AttackSurfaceComponent(
                name=name,
                component_type=ctype,
                risk_level=finding.severity,
                source_files=[],
            )
        comp = seen_types[name]
        # Upgrade risk level if this finding is more severe
        if _sev_rank(finding.severity) > _sev_rank(comp.risk_level):
            comp.risk_level = finding.severity
        for ev in finding.evidence:
            if ev.file_path not in comp.source_files:
                comp.source_files.append(ev.file_path)

    # Always include the "External User" node as the entry-point
    if seen_types:
        seen_types.setdefault(
            "External User",
            AttackSurfaceComponent(
                name="External User",
                component_type="external",
                risk_level="info",
            ),
        )

    components = list(seen_types.values())

    # Build edges — only include those whose endpoints are both present
    present_names = {c.name for c in components}
    edges: list[ArchitectureEdge] = []
    for src, dst, label in _STATIC_EDGES:
        if src in present_names and dst in present_names:
            edges.append(ArchitectureEdge(source=src, target=dst, label=label))

    return components, edges


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEV_RANKS = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _sev_rank(severity: str) -> int:
    return _SEV_RANKS.get(severity, 0)


def _collect_evidence(findings: list[Finding], max_items: int = 10) -> list[Evidence]:
    """Gather up to *max_items* evidence pieces from a list of findings."""
    evidence: list[Evidence] = []
    for f in findings:
        for e in f.evidence:
            evidence.append(e)
            if len(evidence) >= max_items:
                return evidence
    return evidence
