# ---------------------------------------------------------------------------
# rules/secret_rules.py — Token and secret storage rules
#
# These rules detect plaintext secrets, API keys, tokens, and other
# credential-like values in configuration files.
# ---------------------------------------------------------------------------
"""
Rules for detecting tokens, secrets, and credential-like values in config.
"""

from __future__ import annotations

import re

from openclaw_audit.models import Evidence, Finding, LoadedDocument
from openclaw_audit.rules.base import BaseRule
from openclaw_audit.utils.patterns import SECRET_KEY_NAMES, HIGH_ENTROPY_VALUE


# ---------------------------------------------------------------------------
# Rule: TOKEN_STORAGE_RISK
# ---------------------------------------------------------------------------
# Purpose:
#     Detect API tokens, passwords, or secrets stored in plaintext
#     configuration files.
# Why this matters:
#     Plaintext secrets in config files are trivially extractable if the
#     repo is leaked, if the file permissions are too broad, or if
#     backups are not encrypted.  This is one of the most common root
#     causes of credential compromise.
# ---------------------------------------------------------------------------

class TokenStorageRiskRule(BaseRule):
    rule_id = "TOKEN_STORAGE_RISK"
    category = "TOKEN_STORAGE_RISK"
    severity = "critical"
    description = (
        "Detects API tokens, passwords, or secret-like values stored "
        "in plaintext configuration files."
    )
    recommendation = (
        "Store secrets in a dedicated secrets manager (e.g. Vault, AWS "
        "Secrets Manager).  Use environment-variable references instead "
        "of hard-coded values.  Never commit secrets to version control."
    )

    # Only flag .env, .ini, .json, .yaml, .toml — not source code (too noisy)
    _CONFIG_TYPES = {"json", "yaml", "toml", "env", "ini"}

    def apply(self, document: LoadedDocument) -> list[Finding]:
        if document.file.file_type not in self._CONFIG_TYPES:
            return []

        evidence: list[Evidence] = []

        # Structured data: look for secret-ish keys with high-entropy values
        if document.parsed_data is not None:
            for path, value in self._key_search(document.parsed_data, SECRET_KEY_NAMES):
                val_str = str(value)
                if HIGH_ENTROPY_VALUE.search(val_str) and len(val_str) >= 8:
                    evidence.append(
                        Evidence(
                            file_path=document.file.relative_path,
                            matched_text=f"{path} = <REDACTED>",
                            context="High-entropy value in secret-like key",
                        )
                    )

        # Text scan: look for KEY=VALUE patterns with secret-ish key names
        for idx, line in enumerate(document.lines, start=1):
            if SECRET_KEY_NAMES.search(line) and "=" in line:
                parts = line.split("=", 1)
                if len(parts) == 2:
                    value_part = parts[1].strip().strip("\"'")
                    if HIGH_ENTROPY_VALUE.search(value_part) and len(value_part) >= 8:
                        evidence.append(
                            Evidence(
                                file_path=document.file.relative_path,
                                line_number=idx,
                                matched_text=f"{parts[0].strip()} = <REDACTED>",
                                context="Potential plaintext secret",
                            )
                        )

        if not evidence:
            return []

        return [
            self._make_finding(
                title="Plaintext token / secret in config",
                description=(
                    "A configuration file contains a key with a secret-like "
                    "name (e.g. api_key, token, password) whose value appears "
                    "to be a high-entropy credential."
                ),
                evidence=evidence,
                confidence="medium",
                tags=["secret", "token", "credential"],
            )
        ]


# ---------------------------------------------------------------------------
# Rule: POTENTIAL_SECRET_IN_CONFIG
# ---------------------------------------------------------------------------
# Purpose:
#     A broader, lower-confidence check for any configuration key whose
#     name *might* hold a secret, even if the value doesn't look
#     high-entropy.
# Why this matters:
#     Even low-entropy passwords or placeholder tokens may end up in
#     production configs.
# ---------------------------------------------------------------------------

class PotentialSecretInConfigRule(BaseRule):
    rule_id = "POTENTIAL_SECRET_IN_CONFIG"
    category = "POTENTIAL_SECRET_IN_CONFIG"
    severity = "low"
    description = (
        "Flags configuration keys whose names suggest they may hold "
        "secrets, even if the value is not obviously high-entropy."
    )
    recommendation = (
        "Review flagged keys and ensure their values are not real "
        "credentials.  Consider using environment-variable references."
    )

    _CONFIG_TYPES = {"json", "yaml", "toml", "env", "ini"}

    def apply(self, document: LoadedDocument) -> list[Finding]:
        if document.file.file_type not in self._CONFIG_TYPES:
            return []

        evidence: list[Evidence] = []

        if document.parsed_data is not None:
            for path, value in self._key_search(document.parsed_data, SECRET_KEY_NAMES):
                val_str = str(value)
                # Skip obviously empty/placeholder values
                if val_str in ("", "null", "None", "TODO", "CHANGEME", "xxx"):
                    continue
                evidence.append(
                    Evidence(
                        file_path=document.file.relative_path,
                        matched_text=f"{path} = <value present>",
                        context="Secret-like key with a non-empty value",
                    )
                )

        if not evidence:
            return []

        return [
            self._make_finding(
                title="Potential secret in configuration",
                description=(
                    "A configuration key with a secret-like name has a "
                    "non-empty value.  This may warrant manual review."
                ),
                evidence=evidence,
                confidence="low",
                tags=["secret", "config"],
            )
        ]
