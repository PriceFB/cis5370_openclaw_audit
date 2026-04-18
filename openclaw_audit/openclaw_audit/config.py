# ---------------------------------------------------------------------------
# config.py — Scan configuration model
#
# Centralises every tuneable knob for a scan run into one typed object.
# This keeps function signatures short and makes it easy to serialise or
# log the exact configuration that produced a given set of results.
# ---------------------------------------------------------------------------
"""
Immutable scan configuration.

A ``ScanConfig`` is built once from CLI flags and then threaded through
the entire pipeline so that every component can inspect the same settings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Default values
# ---------------------------------------------------------------------------

DEFAULT_OUTPUT_DIR = Path("./scan_output")

DEFAULT_INCLUDE_PATTERNS: list[str] = [
    "*.json", "*.yaml", "*.yml", "*.toml",
    "*.py", "*.ts", "*.js",
    "*.md", "*.txt",
    "*.env", "*.ini",
    "Dockerfile", "docker-compose.yml",
]

DEFAULT_EXCLUDE_DIRS: list[str] = [
    ".git", "node_modules", "__pycache__",
    "dist", "build", ".venv",
    ".mypy_cache", ".ruff_cache",
    "scan_output",
]

SEVERITY_LEVELS: list[str] = ["info", "low", "medium", "high", "critical"]


# ---------------------------------------------------------------------------
# ScanConfig dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScanConfig:
    """All user-facing settings for a single scan invocation."""

    target_path: Path
    output_dir: Path = DEFAULT_OUTPUT_DIR

    formats: list[str] = field(default_factory=lambda: ["json", "csv", "mermaid"])
    include_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_INCLUDE_PATTERNS))
    exclude_dirs: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE_DIRS))

    min_severity: str = "info"
    verbose: bool = False
    pretty: bool = True
