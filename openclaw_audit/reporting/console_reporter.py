# ---------------------------------------------------------------------------
# reporting/console_reporter.py — Rich terminal summary
#
# Prints a colour-coded summary to the terminal so the user gets
# immediate feedback without opening any files.
# ---------------------------------------------------------------------------
"""
Console reporter: prints a colourful risk summary using Rich.
"""

from __future__ import annotations

from collections import Counter

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from openclaw_audit.models import ScanResult


# Severity → Rich colour mapping
_SEVERITY_STYLE: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}


def print_summary(result: ScanResult, console: Console | None = None) -> None:
    """
    Print a human-readable summary of the scan result.

    If *console* is ``None``, a new one targeting stdout is created.
    """
    if console is None:
        console = Console()

    # -- Risk score banner -------------------------------------------------
    band_color = {
        "Critical": "bold red",
        "High": "red",
        "Moderate": "yellow",
        "Low": "green",
    }.get(result.risk_band, "white")

    score_text = (
        f"[bold]Risk Score:[/bold]  {result.risk_score} / 100  "
        f"[{band_color}]({result.risk_band})[/{band_color}]"
    )

    console.print(Panel(score_text, title="Risk Assessment", border_style="cyan"))

    # -- Summary stats -----------------------------------------------------
    console.print(f"\n  Files scanned : {result.files_scanned}")
    console.print(f"  Total findings: {len(result.findings)}")

    # -- Severity breakdown ------------------------------------------------
    severity_counts = Counter(f.severity for f in result.findings)
    if severity_counts:
        sev_table = Table(title="Findings by Severity", show_lines=False)
        sev_table.add_column("Severity", justify="center")
        sev_table.add_column("Count", justify="right")

        for sev in ("critical", "high", "medium", "low", "info"):
            count = severity_counts.get(sev, 0)
            if count:
                style = _SEVERITY_STYLE.get(sev, "white")
                sev_table.add_row(f"[{style}]{sev}[/{style}]", str(count))

        console.print()
        console.print(sev_table)

    # -- Category breakdown ------------------------------------------------
    if result.category_scores:
        cat_table = Table(title="Category Risk Contributions", show_lines=False)
        cat_table.add_column("Category")
        cat_table.add_column("Score", justify="right")

        for cat, score in sorted(
            result.category_scores.items(), key=lambda x: -x[1]
        ):
            cat_table.add_row(cat, f"{score:.1f}")

        console.print()
        console.print(cat_table)

    # -- Top findings ------------------------------------------------------
    top_findings = sorted(
        result.findings,
        key=lambda f: _sev_rank(f.severity),
        reverse=True,
    )[:5]

    if top_findings:
        console.print("\n[bold]Top Findings:[/bold]")
        for f in top_findings:
            style = _SEVERITY_STYLE.get(f.severity, "white")
            console.print(
                f"  [{style}]{f.severity:>8}[/{style}]  "
                f"[bold]{f.category}[/bold] — {f.title}"
            )

    console.print()


def _sev_rank(severity: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 0)
