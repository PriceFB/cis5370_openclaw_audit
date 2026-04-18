# ---------------------------------------------------------------------------
# reporting/json_reporter.py — Findings JSON output
#
# Writes a machine-readable JSON file containing all findings, the risk
# score, and a summary.  This is the primary artifact for downstream
# tooling or report generation.
# ---------------------------------------------------------------------------
"""
JSON reporter: writes ``findings.json``.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from openclaw_audit.config import ScanConfig
from openclaw_audit.models import ScanResult


def write_json(result: ScanResult, config: ScanConfig) -> Path:
    """
    Serialise *result* to ``findings.json`` inside the output directory.

    Returns the path to the written file.
    """
    output_path = config.output_dir / "findings.json"

    payload = {
        "tool": "openclaw-audit",
        "target": result.target_path,
        "files_scanned": result.files_scanned,
        "risk_score": result.risk_score,
        "risk_band": result.risk_band,
        "category_scores": result.category_scores,
        "total_findings": len(result.findings),
        "findings": [asdict(f) for f in result.findings],
        "components": [asdict(c) for c in result.components],
    }

    indent = 2 if config.pretty else None
    output_path.write_text(
        json.dumps(payload, indent=indent, default=str),
        encoding="utf-8",
    )

    return output_path
