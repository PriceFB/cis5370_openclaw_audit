# ---------------------------------------------------------------------------
# scanner.py — Top-level scan orchestration
#
# This is the "main pipeline" that ties every subsystem together:
#
#   1. Discover files          (discovery.py)
#   2. Load / parse documents  (loaders.py)
#   3. Run rules on each doc   (rules/)
#   4. Correlate findings      (correlators.py)
#   5. Score risk              (risk.py)
#   6. Build architecture map  (correlators.py)
#
# The function ``run_scan()`` is the single entry-point called by the CLI.
# ---------------------------------------------------------------------------
"""
Scan orchestration: drives discovery → loading → rules → correlation → scoring.
"""

from __future__ import annotations

import logging

from openclaw_audit.config import ScanConfig
from openclaw_audit.discovery import discover_files
from openclaw_audit.loaders import load_documents
from openclaw_audit.models import Finding, LoadedDocument, ScanResult
from openclaw_audit.rules import get_all_rules
from openclaw_audit.correlators import correlate_findings, infer_architecture
from openclaw_audit.risk import compute_risk
from openclaw_audit.utils.logging import configure_logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_scan(config: ScanConfig) -> ScanResult:
    """
    Execute the full scan pipeline and return a ``ScanResult``.

    This is the only function the CLI needs to call.  Every other module
    is reached indirectly through this pipeline.
    """
    configure_logging(verbose=config.verbose)

    # -- Step 1: Discover candidate files ----------------------------------
    logger.info("Step 1/6 — discovering files …")
    files = discover_files(config)

    # -- Step 2: Load and parse documents ----------------------------------
    logger.info("Step 2/6 — loading documents …")
    documents = load_documents(files)

    # -- Step 3: Apply rules -----------------------------------------------
    logger.info("Step 3/6 — running %d rules …", len(get_all_rules()))
    raw_findings = _apply_rules(documents)

    # -- Step 4: Correlate / synthesise ------------------------------------
    logger.info("Step 4/6 — correlating findings …")
    all_findings = correlate_findings(raw_findings)

    # -- Step 5: Filter by min_severity ------------------------------------
    filtered = _filter_severity(all_findings, config.min_severity)

    # -- Step 6: Score risk ------------------------------------------------
    logger.info("Step 5/6 — computing risk score …")
    risk_score, risk_band, category_scores = compute_risk(filtered)

    # -- Step 6b: Infer architecture graph ---------------------------------
    logger.info("Step 6/6 — inferring architecture …")
    components, edges = infer_architecture(filtered)

    return ScanResult(
        target_path=str(config.target_path),
        files_scanned=len(documents),
        findings=filtered,
        components=components,
        edges=edges,
        risk_score=risk_score,
        risk_band=risk_band,
        category_scores=category_scores,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _apply_rules(documents: list[LoadedDocument]) -> list[Finding]:
    """Run every registered rule against every loaded document."""
    rules = get_all_rules()
    findings: list[Finding] = []

    for doc in documents:
        for rule in rules:
            try:
                hits = rule.apply(doc)
                findings.extend(hits)
            except Exception:
                logger.exception(
                    "Rule %s raised on %s — skipping",
                    rule.rule_id,
                    doc.file.relative_path,
                )

    logger.info("Rules produced %d raw findings", len(findings))
    return findings


SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _filter_severity(findings: list[Finding], min_severity: str) -> list[Finding]:
    """Remove findings below the requested minimum severity."""
    try:
        threshold = SEVERITY_ORDER.index(min_severity)
    except ValueError:
        threshold = 0

    return [
        f for f in findings
        if SEVERITY_ORDER.index(f.severity) >= threshold
    ]
