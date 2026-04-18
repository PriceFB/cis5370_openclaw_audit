# ---------------------------------------------------------------------------
# rules/base.py — Abstract base class for all audit rules
#
# Every concrete rule inherits from ``BaseRule`` and implements ``apply()``.
# The base class carries metadata (rule_id, severity, description, …) that
# the CLI, reporters, and explain command all rely on.
#
# Design rationale:
#   • One class per rule keeps each detection self-contained and testable.
#   • Metadata lives directly on the class so that ``rules list`` and
#     ``explain`` don't need a separate registry.
#   • Helper methods (_text_scan, _key_search) reduce boilerplate for the
#     two most common detection strategies: line-by-line regex and
#     recursive dictionary key search.
# ---------------------------------------------------------------------------
"""
Base class and helper utilities for all audit rules.
"""

from __future__ import annotations

import re
import uuid
from abc import ABC, abstractmethod
from typing import Any

from openclaw_audit.models import Evidence, Finding, LoadedDocument


class BaseRule(ABC):
    """
    Abstract base for an audit rule.

    Subclasses must set the class-level metadata attributes and implement
    ``apply()`` which inspects a single ``LoadedDocument`` and returns
    zero or more ``Finding`` objects.
    """

    # -- Metadata (override in every subclass) -----------------------------
    rule_id: str = "UNSET"
    category: str = "UNSET"
    severity: str = "info"
    description: str = ""
    recommendation: str = ""

    # -- Abstract entry-point ----------------------------------------------

    @abstractmethod
    def apply(self, document: LoadedDocument) -> list[Finding]:
        """
        Inspect *document* and return any findings.

        Each returned ``Finding`` should carry at least one ``Evidence``
        item referencing the specific file and (ideally) line number
        where the pattern was observed.
        """

    # -- Convenience: build a Finding pre-populated with rule metadata -----

    def _make_finding(
        self,
        title: str,
        description: str,
        evidence: list[Evidence],
        *,
        confidence: str = "medium",
        tags: list[str] | None = None,
    ) -> Finding:
        """
        Create a ``Finding`` with this rule's metadata already filled in.

        ``id`` is a short unique string derived from the rule_id.
        """
        short_id = f"{self.rule_id}-{uuid.uuid4().hex[:8]}"
        return Finding(
            id=short_id,
            category=self.category,
            severity=self.severity,
            confidence=confidence,
            title=title,
            description=description,
            recommendation=self.recommendation,
            evidence=evidence,
            tags=tags or [],
        )

    # -- Convenience: line-by-line regex scan ------------------------------

    @staticmethod
    def _text_scan(
        document: LoadedDocument,
        pattern: re.Pattern[str],
    ) -> list[Evidence]:
        """
        Scan every line of the document for *pattern*, returning Evidence
        for each match with the 1-based line number.
        """
        hits: list[Evidence] = []
        for idx, line in enumerate(document.lines, start=1):
            if pattern.search(line):
                hits.append(
                    Evidence(
                        file_path=document.file.relative_path,
                        line_number=idx,
                        matched_text=line.strip(),
                    )
                )
        return hits

    # -- Convenience: recursive key search in parsed dicts -----------------

    @staticmethod
    def _key_search(
        data: Any,
        key_pattern: re.Pattern[str],
        *,
        _path: str = "",
    ) -> list[tuple[str, Any]]:
        """
        Recursively walk a nested dict/list looking for keys that match
        *key_pattern*.  Returns a list of ``(dotted_path, value)`` tuples.
        """
        results: list[tuple[str, Any]] = []

        if isinstance(data, dict):
            for key, value in data.items():
                current = f"{_path}.{key}" if _path else key
                if key_pattern.search(str(key)):
                    results.append((current, value))
                results.extend(
                    BaseRule._key_search(value, key_pattern, _path=current)
                )
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current = f"{_path}[{i}]"
                results.extend(
                    BaseRule._key_search(item, key_pattern, _path=current)
                )

        return results
