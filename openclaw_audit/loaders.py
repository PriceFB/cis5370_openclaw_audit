# ---------------------------------------------------------------------------
# loaders.py — Safe file loading with structured-parse fallback
#
# For each discovered file the loader:
#   1. Reads the raw text content (UTF-8, with fallback to latin-1).
#   2. Attempts structured parsing (JSON / YAML / TOML) when the file
#      extension suggests it.
#   3. Falls back gracefully to plain-text mode on any parse error.
#
# The result is a LoadedDocument that downstream rules can inspect either
# as structured data or as raw text lines.
# ---------------------------------------------------------------------------
"""
Safe file reader that produces ``LoadedDocument`` objects for the rule engine.
"""

from __future__ import annotations

import logging
from pathlib import Path

from openclaw_audit.models import DiscoveredFile, LoadedDocument
from openclaw_audit.parsers import try_parse

logger = logging.getLogger(__name__)

# Maximum file size we'll attempt to read (5 MB).  Anything larger is
# unlikely to be a configuration file and could slow down the scan.
MAX_FILE_SIZE = 5 * 1024 * 1024


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_documents(files: list[DiscoveredFile]) -> list[LoadedDocument]:
    """Load and optionally parse each discovered file, returning documents."""
    documents: list[LoadedDocument] = []

    for discovered in files:
        doc = _load_one(discovered)
        if doc is not None:
            documents.append(doc)

    logger.info("Loaded %d / %d files successfully", len(documents), len(files))
    return documents


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_one(file: DiscoveredFile) -> LoadedDocument | None:
    """
    Read a single file and return a ``LoadedDocument``, or ``None`` if
    the file is unreadable or too large.
    """
    if file.size_bytes > MAX_FILE_SIZE:
        logger.debug("Skipping oversized file (%d bytes): %s", file.size_bytes, file.path)
        return None

    raw_text = _read_text(file.path)
    if raw_text is None:
        return None

    lines = raw_text.splitlines()

    # Attempt structured parsing based on file type
    parsed_data, parse_format = try_parse(raw_text, file.file_type)

    return LoadedDocument(
        file=file,
        raw_text=raw_text,
        lines=lines,
        parsed_data=parsed_data,
        parse_format=parse_format,
    )


def _read_text(path: Path) -> str | None:
    """
    Read a file as text.  Tries UTF-8 first, then falls back to latin-1
    (which never raises a decoding error).
    """
    for encoding in ("utf-8", "latin-1"):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
        except OSError as exc:
            logger.warning("Cannot read %s: %s", path, exc)
            return None

    return None
