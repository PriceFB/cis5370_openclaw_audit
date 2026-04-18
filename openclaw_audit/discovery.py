# ---------------------------------------------------------------------------
# discovery.py — File discovery and classification
#
# This module is the very first step of the scan pipeline.  It recursively
# walks the target directory, applies include/exclude filters, and returns
# a list of DiscoveredFile objects for downstream loading and analysis.
#
# Design goals:
#   • Never crash on permission errors or broken symlinks.
#   • Respect the user's include/exclude preferences.
#   • Classify files by extension so the loader knows which parser to try.
# ---------------------------------------------------------------------------
"""
Recursive file discovery with glob-based include/exclude filtering.
"""

from __future__ import annotations

import fnmatch
import logging
from pathlib import Path

from openclaw_audit.config import ScanConfig
from openclaw_audit.models import DiscoveredFile

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Extension → logical file-type mapping
# ---------------------------------------------------------------------------

EXTENSION_MAP: dict[str, str] = {
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".md": "markdown",
    ".txt": "text",
    ".env": "env",
    ".ini": "ini",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def discover_files(config: ScanConfig) -> list[DiscoveredFile]:
    """
    Walk *config.target_path* and return every file matching the include
    patterns while skipping excluded directories.

    Returns a sorted list of ``DiscoveredFile`` objects.
    """
    results: list[DiscoveredFile] = []
    target = config.target_path.resolve()

    for path in _walk_safe(target, config.exclude_dirs):
        if not _matches_include(path, config.include_patterns):
            continue

        relative = _safe_relative(path, target)
        file_type = _classify(path)
        size = _safe_size(path)

        results.append(
            DiscoveredFile(
                path=path,
                relative_path=relative,
                file_type=file_type,
                size_bytes=size,
            )
        )

    results.sort(key=lambda f: f.relative_path)
    logger.info("Discovered %d candidate files under %s", len(results), target)
    return results


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _walk_safe(root: Path, exclude_dirs: list[str]) -> list[Path]:
    """Recursively yield files, silently skipping unreadable entries."""
    files: list[Path] = []
    try:
        for entry in sorted(root.iterdir()):
            if entry.is_dir():
                if entry.name in exclude_dirs:
                    logger.debug("Excluding directory: %s", entry)
                    continue
                files.extend(_walk_safe(entry, exclude_dirs))
            elif entry.is_file():
                files.append(entry)
    except PermissionError:
        logger.warning("Permission denied: %s", root)
    except OSError as exc:
        logger.warning("OS error walking %s: %s", root, exc)
    return files


def _matches_include(path: Path, patterns: list[str]) -> bool:
    """Return True if *path* matches at least one include glob pattern."""
    name = path.name
    for pattern in patterns:
        if fnmatch.fnmatch(name, pattern):
            return True
    return False


def _classify(path: Path) -> str:
    """Map a file's extension (or name) to a logical type string."""
    # Special-case files without meaningful extensions
    if path.name.lower() in ("dockerfile",):
        return "dockerfile"
    if path.name.lower().startswith("docker-compose"):
        return "yaml"

    return EXTENSION_MAP.get(path.suffix.lower(), "text")


def _safe_relative(path: Path, root: Path) -> str:
    """Compute a relative path string, falling back to the absolute path."""
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _safe_size(path: Path) -> int:
    """Return file size in bytes, or 0 on error."""
    try:
        return path.stat().st_size
    except OSError:
        return 0
