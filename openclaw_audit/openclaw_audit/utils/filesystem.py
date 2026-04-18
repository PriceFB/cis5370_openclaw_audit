# ---------------------------------------------------------------------------
# utils/filesystem.py — Filesystem helper functions
# ---------------------------------------------------------------------------
"""Small utilities for safe path operations."""

from __future__ import annotations

from pathlib import Path


def ensure_dir(path: Path) -> Path:
    """Create *path* (and parents) if it does not exist, then return it."""
    path.mkdir(parents=True, exist_ok=True)
    return path
