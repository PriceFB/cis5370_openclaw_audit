# ---------------------------------------------------------------------------
# risk.py — Risk scoring engine
#
# Turns a list of findings into a single 0–100 score and a human-readable
# risk band.  The model is intentionally simple and fully transparent so
# that every score can be explained in a report or presentation.
#
# Scoring algorithm:
#   1. Each finding has a base severity score:
#        info=1, low=3, medium=6, high=10, critical=15
#   2. Multiply by a confidence factor:
#        high=1.0, medium=0.75, low=0.5
#   3. Sum all weighted scores.
#   4. Clamp to 0–100.
#   5. Map to a risk band:
#        0–19  → Low
#        20–39 → Moderate
#        40–69 → High
#        70–100→ Critical
# ---------------------------------------------------------------------------
"""
Weighted risk scoring with per-category breakdowns.
"""

from __future__ import annotations

from collections import defaultdict

from openclaw_audit.models import Finding

# ---------------------------------------------------------------------------
# Severity base scores
# ---------------------------------------------------------------------------

SEVERITY_SCORES: dict[str, int] = {
    "info": 1,
    "low": 3,
    "medium": 6,
    "high": 10,
    "critical": 15,
}

# ---------------------------------------------------------------------------
# Confidence multipliers
# ---------------------------------------------------------------------------

CONFIDENCE_MULTIPLIERS: dict[str, float] = {
    "high": 1.0,
    "medium": 0.75,
    "low": 0.5,
}

# ---------------------------------------------------------------------------
# Risk bands
# ---------------------------------------------------------------------------

RISK_BANDS: list[tuple[int, str]] = [
    (70, "Critical"),
    (40, "High"),
    (20, "Moderate"),
    (0,  "Low"),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_risk(
    findings: list[Finding],
) -> tuple[int, str, dict[str, float]]:
    """
    Compute a risk score from a list of findings.

    Returns:
        ``(total_score, risk_band, category_scores)``
        where *category_scores* maps each finding category to its
        subtotal contribution.
    """
    category_totals: dict[str, float] = defaultdict(float)

    for finding in findings:
        base = SEVERITY_SCORES.get(finding.severity, 1)
        multiplier = CONFIDENCE_MULTIPLIERS.get(finding.confidence, 0.5)
        weighted = base * multiplier
        category_totals[finding.category] += weighted

    raw_total = sum(category_totals.values())
    clamped = int(min(max(raw_total, 0), 100))

    band = _score_to_band(clamped)

    return clamped, band, dict(category_totals)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _score_to_band(score: int) -> str:
    """Map a 0–100 score to a risk band label."""
    for threshold, label in RISK_BANDS:
        if score >= threshold:
            return label
    return "Low"
