# ---------------------------------------------------------------------------
# rules/ — Detection rule registry
#
# Every rule module in this package registers its rules via the
# ``get_all_rules()`` function.  Adding a new rule is as simple as:
#   1. Create a new module under rules/
#   2. Define one or more subclasses of BaseRule
#   3. Import and append them in this file
# ---------------------------------------------------------------------------
"""
Central registry that collects all audit rules from sub-modules.
"""

from __future__ import annotations

from openclaw_audit.rules.base import BaseRule

from openclaw_audit.rules.network_rules import (
    NonLocalhostBindRule,
    TrustedProxyRule,
)
from openclaw_audit.rules.auth_rules import (
    ApiExposureRule,
    ExposedAdminSurfaceRule,
)
from openclaw_audit.rules.plugin_rules import (
    PluginTrustRiskRule,
)
from openclaw_audit.rules.workspace_rules import (
    WeakAgentIsolationRule,
    WorkspacePathRiskRule,
    BroadFilesystemAccessRule,
)
from openclaw_audit.rules.node_rules import (
    NodeCommandSurfaceRule,
)
from openclaw_audit.rules.secret_rules import (
    TokenStorageRiskRule,
    PotentialSecretInConfigRule,
)
from openclaw_audit.rules.execution_rules import (
    ExecutionSurfaceRule,
    UnrestrictedToolingRule,
    SharedAgentHighPrivRule,
)


def get_all_rules() -> list[BaseRule]:
    """Return a fresh list containing one instance of every registered rule."""
    return [
        # Network / exposure
        NonLocalhostBindRule(),
        TrustedProxyRule(),

        # API / admin
        ApiExposureRule(),
        ExposedAdminSurfaceRule(),

        # Plugins
        PluginTrustRiskRule(),

        # Workspace / isolation
        WeakAgentIsolationRule(),
        WorkspacePathRiskRule(),
        BroadFilesystemAccessRule(),

        # Nodes / devices
        NodeCommandSurfaceRule(),

        # Secrets / tokens
        TokenStorageRiskRule(),
        PotentialSecretInConfigRule(),

        # Execution / tooling
        ExecutionSurfaceRule(),
        UnrestrictedToolingRule(),
        SharedAgentHighPrivRule(),
    ]
