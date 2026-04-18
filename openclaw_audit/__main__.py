# ---------------------------------------------------------------------------
# __main__.py — Allows running the package directly: python -m openclaw_audit
# ---------------------------------------------------------------------------
"""
Entry-point for ``python -m openclaw_audit``.

This simply delegates to the Typer CLI application defined in cli.py.
"""

from openclaw_audit.cli import app

app()
