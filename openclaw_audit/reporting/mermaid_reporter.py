# ---------------------------------------------------------------------------
# reporting/mermaid_reporter.py — Mermaid architecture diagram output
#
# Generates a `.mmd` file containing a Mermaid flowchart that visualises
# the inferred architectural components and their relationships.
#
# Risky components are annotated with their risk level so that the
# diagram doubles as a visual risk map during a presentation.
# ---------------------------------------------------------------------------
"""
Mermaid reporter: writes ``architecture.mmd``.
"""

from __future__ import annotations

from pathlib import Path

from openclaw_audit.config import ScanConfig
from openclaw_audit.models import ScanResult


# Mermaid node shapes by component type.
# Every shape uses a syntax that supports quoted labels inside.
_SHAPES: dict[str, tuple[str, str]] = {
    "external":  ("([", "])"),    # stadium / pill shape
    "gateway":   ("[",  "]"),     # rectangle
    "api":       ("[",  "]"),
    "dashboard": ("[",  "]"),
    "agent":     ("[[", "]]"),    # subroutine
    "plugin":    ("{{", "}}"),    # hexagon
    "workspace": ("[(", ")]"),    # cylinder
    "node":      ("([", "])"),    # stadium (safe alternative to asymmetric)
    "secret":    ("([", "])"),
}


def write_mermaid(result: ScanResult, config: ScanConfig) -> Path:
    """
    Generate a Mermaid flowchart from the inferred architecture.

    Returns the path to the written ``.mmd`` file.
    """
    output_path = config.output_dir / "architecture.mmd"
    lines: list[str] = ["flowchart TD"]

    # -- Node definitions --------------------------------------------------
    for comp in result.components:
        node_id = _safe_id(comp.name)
        label = comp.name
        if comp.risk_level in ("high", "critical"):
            label += f" - {comp.risk_level.upper()} RISK"

        open_br, close_br = _SHAPES.get(comp.component_type, ("[", "]"))
        # Wrap the label in double quotes so Mermaid treats square
        # brackets and special characters inside it as literal text.
        lines.append(f'    {node_id}{open_br}"{label}"{close_br}')

    # -- Edge definitions --------------------------------------------------
    for edge in result.edges:
        src = _safe_id(edge.source)
        dst = _safe_id(edge.target)
        if edge.label:
            lines.append(f"    {src} -->|{edge.label}| {dst}")
        else:
            lines.append(f"    {src} --> {dst}")

    # -- Risk styling ------------------------------------------------------
    high_risk_ids = [
        _safe_id(c.name)
        for c in result.components
        if c.risk_level in ("high", "critical")
    ]
    if high_risk_ids:
        lines.append("")
        lines.append(
            "    classDef risky fill:#ff6b6b,stroke:#c0392b,color:#fff"
        )
        lines.append(f"    class {','.join(high_risk_ids)} risky")

    content = "\n".join(lines) + "\n"
    output_path.write_text(content, encoding="utf-8")

    return output_path


def _safe_id(name: str) -> str:
    """Convert a human-readable name into a Mermaid-safe node ID."""
    return name.replace(" ", "_").replace("/", "_").replace("-", "_")
