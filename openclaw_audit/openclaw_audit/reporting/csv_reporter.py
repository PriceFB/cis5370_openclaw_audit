# ---------------------------------------------------------------------------
# reporting/csv_reporter.py — Attack-surface CSV output
#
# Writes a flat CSV that is easy to open in Excel / Google Sheets for
# quick triage or inclusion in a presentation slide.
# ---------------------------------------------------------------------------
"""
CSV reporter: writes ``attack_surface.csv``.
"""

from __future__ import annotations

import csv
from pathlib import Path

from openclaw_audit.config import ScanConfig
from openclaw_audit.models import ScanResult


CSV_COLUMNS = [
    "id",
    "category",
    "severity",
    "confidence",
    "title",
    "file_path",
    "line_number",
    "matched_pattern",
    "risk_reason",
    "recommendation",
]


def write_csv(result: ScanResult, config: ScanConfig) -> Path:
    """
    Write a flat CSV of findings to ``attack_surface.csv``.

    Each row corresponds to one piece of evidence within a finding.
    If a finding has multiple evidence items, each gets its own row
    so that the spreadsheet is easy to filter by file.
    """
    output_path = config.output_dir / "attack_surface.csv"

    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()

        for finding in result.findings:
            if finding.evidence:
                for ev in finding.evidence:
                    writer.writerow({
                        "id": finding.id,
                        "category": finding.category,
                        "severity": finding.severity,
                        "confidence": finding.confidence,
                        "title": finding.title,
                        "file_path": ev.file_path,
                        "line_number": ev.line_number or "",
                        "matched_pattern": ev.matched_text or "",
                        "risk_reason": finding.description,
                        "recommendation": finding.recommendation,
                    })
            else:
                # Findings with no evidence still get a row
                writer.writerow({
                    "id": finding.id,
                    "category": finding.category,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "title": finding.title,
                    "file_path": "",
                    "line_number": "",
                    "matched_pattern": "",
                    "risk_reason": finding.description,
                    "recommendation": finding.recommendation,
                })

    return output_path
