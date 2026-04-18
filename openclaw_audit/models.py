# ---------------------------------------------------------------------------
# models.py — Core data models for the audit pipeline
#
# Every piece of data that flows through discovery → loading → rule engine →
# correlation → scoring → reporting is represented by one of these typed
# dataclasses.  Keeping them in a single file makes it trivially easy to
# see the full "shape" of the system.
# ---------------------------------------------------------------------------
"""
Typed data models used across the openclaw-audit pipeline.

Models
------
- ``DiscoveredFile``         — a file found during directory traversal
- ``LoadedDocument``         — parsed / raw content of a single file
- ``Evidence``               — one piece of proof supporting a finding
- ``Finding``                — a single security-relevant observation
- ``AttackSurfaceComponent`` — an inferred architectural component
- ``ArchitectureEdge``       — a directional link between two components
- ``ScanResult``             — aggregated output of a full scan
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

@dataclass
class DiscoveredFile:
    """Metadata about a file found during recursive directory traversal."""

    path: Path
    relative_path: str
    file_type: str          # e.g. "json", "yaml", "py", "text"
    size_bytes: int


# ---------------------------------------------------------------------------
# Document loading
# ---------------------------------------------------------------------------

@dataclass
class LoadedDocument:
    """
    The result of loading and (optionally) parsing a single file.

    If structured parsing succeeds, ``parsed_data`` holds a dict / list.
    Otherwise, ``raw_text`` holds the file content as a plain string.
    ``lines`` always holds a list of individual lines for line-number
    references.
    """

    file: DiscoveredFile
    raw_text: str = ""
    lines: list[str] = field(default_factory=list)
    parsed_data: Any | None = None
    parse_format: str = "text"          # "json", "yaml", "toml", or "text"


# ---------------------------------------------------------------------------
# Evidence and findings
# ---------------------------------------------------------------------------

@dataclass
class Evidence:
    """A concrete piece of evidence supporting a Finding."""

    file_path: str
    line_number: int | None = None
    matched_text: str | None = None
    context: str | None = None


@dataclass
class Finding:
    """
    A single security-relevant observation produced by a rule or correlator.

    Findings are the primary output of the rule engine.  Each Finding
    carries enough context to be useful on its own — category, severity,
    human-readable description, actionable recommendation, and one or
    more pieces of Evidence.
    """

    id: str
    category: str
    severity: str               # info | low | medium | high | critical
    confidence: str             # high | medium | low
    title: str
    description: str
    recommendation: str
    evidence: list[Evidence] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Architecture graph
# ---------------------------------------------------------------------------

@dataclass
class AttackSurfaceComponent:
    """An inferred architectural component of the target system."""

    name: str
    component_type: str         # e.g. "gateway", "agent", "plugin"
    risk_level: str             # low | medium | high | critical
    source_files: list[str] = field(default_factory=list)


@dataclass
class ArchitectureEdge:
    """A directional relationship between two components."""

    source: str
    target: str
    label: str = ""


# ---------------------------------------------------------------------------
# Scan result
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """
    Aggregated output of a complete scan.

    This is the top-level object passed to every reporter.
    """

    target_path: str
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    components: list[AttackSurfaceComponent] = field(default_factory=list)
    edges: list[ArchitectureEdge] = field(default_factory=list)
    risk_score: int = 0
    risk_band: str = "Low"
    category_scores: dict[str, float] = field(default_factory=dict)
