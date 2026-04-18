# ---------------------------------------------------------------------------
# cli.py — Command-line interface for openclaw-audit
#
# Uses Typer for a developer-friendly CLI with automatic help generation.
# All heavy lifting is delegated to scanner.py; this module only handles
# argument parsing, flag validation, and output orchestration.
# ---------------------------------------------------------------------------
"""
CLI commands for the ``openclaw-audit`` tool.

Usage examples::

    openclaw-audit scan /path/to/repo
    openclaw-audit scan /path/to/repo --output-dir ./out --verbose
    openclaw-audit rules list
    openclaw-audit explain NON_LOCALHOST_BIND
    openclaw-audit version
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from openclaw_audit import __version__
from openclaw_audit.config import ScanConfig

# ---------------------------------------------------------------------------
# Typer application and shared Rich console
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="openclaw-audit",
    help="Static security audit CLI for the OpenClaw orchestration framework.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()


# ---------------------------------------------------------------------------
# Subcommand: scan
# ---------------------------------------------------------------------------

@app.command()
def scan(
    target: Path = typer.Argument(
        ...,
        help="Path to the directory to scan.",
        exists=True,
        file_okay=False,
        readable=True,
        resolve_path=True,
    ),
    output_dir: Path = typer.Option(
        Path("./scan_output"),
        "--output-dir", "-o",
        help="Directory for output artifacts.",
    ),
    format: str = typer.Option(
        "json,csv,mermaid",
        "--format", "-f",
        help="Comma-separated output formats: json, csv, mermaid.",
    ),
    min_severity: str = typer.Option(
        "info",
        "--min-severity",
        help="Minimum severity to include in reports (info/low/medium/high/critical).",
    ),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Exit non-zero if any finding meets this severity or higher.",
    ),
    include: str = typer.Option(
        "*.json,*.yaml,*.yml,*.toml,*.py,*.ts,*.js,*.md,*.txt,*.env,*.ini,Dockerfile,docker-compose.yml",
        "--include",
        help="Comma-separated glob patterns for files to include.",
    ),
    exclude: str = typer.Option(
        ".git,node_modules,__pycache__,dist,build,.venv,.mypy_cache,.ruff_cache,scan_output",
        "--exclude",
        help="Comma-separated directory names to exclude.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Enable verbose logging output.",
    ),
    pretty: bool = typer.Option(
        True,
        "--pretty",
        help="Pretty-print JSON output.",
    ),
) -> None:
    """Recursively scan a directory for OpenClaw security patterns."""
    from openclaw_audit.scanner import run_scan
    from openclaw_audit.reporting.console_reporter import print_summary
    from openclaw_audit.reporting.json_reporter import write_json
    from openclaw_audit.reporting.csv_reporter import write_csv
    from openclaw_audit.reporting.mermaid_reporter import write_mermaid

    # -- Build configuration from CLI flags --------------------------------
    formats = [f.strip().lower() for f in format.split(",") if f.strip()]
    include_patterns = [p.strip() for p in include.split(",") if p.strip()]
    exclude_dirs = [d.strip() for d in exclude.split(",") if d.strip()]

    config = ScanConfig(
        target_path=target,
        output_dir=output_dir,
        formats=formats,
        include_patterns=include_patterns,
        exclude_dirs=exclude_dirs,
        min_severity=min_severity.lower(),
        verbose=verbose,
        pretty=pretty,
    )

    # -- Run the scan pipeline ---------------------------------------------
    console.print(f"\n[bold cyan]openclaw-audit v{__version__}[/bold cyan]")
    console.print(f"Scanning: [bold]{config.target_path}[/bold]\n")

    result = run_scan(config)

    # -- Write output artifacts --------------------------------------------
    output_dir.mkdir(parents=True, exist_ok=True)

    if "json" in formats:
        json_path = write_json(result, config)
        console.print(f"  [green]OK[/green] {json_path}")

    if "csv" in formats:
        csv_path = write_csv(result, config)
        console.print(f"  [green]OK[/green] {csv_path}")

    if "mermaid" in formats:
        mmd_path = write_mermaid(result, config)
        console.print(f"  [green]OK[/green] {mmd_path}")

    console.print()

    # -- Print terminal summary --------------------------------------------
    print_summary(result, console)

    # -- Optional fail-on gate ---------------------------------------------
    if fail_on:
        severity_order = ["info", "low", "medium", "high", "critical"]
        threshold = fail_on.lower()
        if threshold in severity_order:
            threshold_idx = severity_order.index(threshold)
            for finding in result.findings:
                if severity_order.index(finding.severity) >= threshold_idx:
                    console.print(
                        f"\n[bold red]FAIL:[/bold red] finding "
                        f"'{finding.category}' meets --fail-on {threshold}"
                    )
                    raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: rules list
# ---------------------------------------------------------------------------

rules_app = typer.Typer(help="Inspect registered audit rules.")
app.add_typer(rules_app, name="rules")


@rules_app.command("list")
def rules_list() -> None:
    """List all registered audit rules with their severity and description."""
    from openclaw_audit.rules import get_all_rules
    from rich.table import Table

    table = Table(title="Registered Audit Rules", show_lines=True)
    table.add_column("Rule ID", style="bold cyan")
    table.add_column("Category")
    table.add_column("Severity", justify="center")
    table.add_column("Description")

    for rule in sorted(get_all_rules(), key=lambda r: r.rule_id):
        severity_color = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }.get(rule.severity, "white")

        table.add_row(
            rule.rule_id,
            rule.category,
            f"[{severity_color}]{rule.severity}[/{severity_color}]",
            rule.description,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Subcommand: explain
# ---------------------------------------------------------------------------

@app.command()
def explain(
    rule_id: str = typer.Argument(..., help="The rule ID to explain."),
) -> None:
    """Show detailed explanation of a specific audit rule."""
    from openclaw_audit.rules import get_all_rules

    for rule in get_all_rules():
        if rule.rule_id.upper() == rule_id.upper():
            console.print(f"\n[bold cyan]{rule.rule_id}[/bold cyan]")
            console.print(f"  Category:    {rule.category}")
            console.print(f"  Severity:    {rule.severity}")
            console.print(f"  Description: {rule.description}")
            console.print(f"  Guidance:    {rule.recommendation}")
            console.print()
            return

    console.print(f"[red]Unknown rule:[/red] {rule_id}")
    raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: version
# ---------------------------------------------------------------------------

@app.command()
def version() -> None:
    """Print the openclaw-audit version."""
    console.print(f"openclaw-audit {__version__}")
