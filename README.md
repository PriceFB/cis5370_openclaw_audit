# openclaw-audit

**Static security audit CLI for the OpenClaw orchestration framework.**

`openclaw-audit` inspects local configuration files, source code, and documentation to identify security-relevant patterns — without ever deploying or connecting to a live system.

---

## Purpose

This tool was built as the coding deliverable for a CIS 5370 cybersecurity course project. It performs **static analysis only**: it walks a repository of OpenClaw-related files, applies a modular rule engine, and produces structured audit artifacts suitable for reports and presentations.

---

## Quick start

```bash
# 1. Clone and install in editable mode
git clone <repo-url>
cd openclaw-audit
pip install -e ".[dev]"

# 2. Run a scan
openclaw-audit scan /path/to/openclaw-repo

# 3. Inspect the outputs
ls ./scan_output/
#   findings.json
#   attack_surface.csv
#   architecture.mmd
```

---

## CLI usage

### Scan a directory

```bash
openclaw-audit scan /path/to/repo
```

### Common flags

```bash
openclaw-audit scan /path/to/repo \
  --output-dir ./scan_output \
  --format json,csv,mermaid \
  --min-severity medium \
  --verbose
```

### Other commands

```bash
openclaw-audit rules list          # List all registered rules
openclaw-audit explain RULE_ID     # Explain a specific rule
openclaw-audit version             # Print version info
```

---

## Output artifacts

| File                | Description                                  |
|---------------------|----------------------------------------------|
| `findings.json`     | Machine-readable list of all findings        |
| `attack_surface.csv`| Spreadsheet-friendly summary for demos       |
| `architecture.mmd`  | Mermaid diagram of inferred architecture     |
| Terminal summary     | Risk score, top findings, category counts    |

---

## Detection categories

| ID                        | What it detects                              |
|---------------------------|----------------------------------------------|
| `NON_LOCALHOST_BIND`      | Services bound to 0.0.0.0 or public IPs     |
| `TRUSTED_PROXY_ENABLED`   | Trusted proxy mode enabled                   |
| `API_EXPOSURE`            | HTTP API / dashboard exposed publicly        |
| `EXPOSED_ADMIN_SURFACE`   | Admin interfaces reachable from outside      |
| `SHARED_AGENT_HIGH_PRIV`  | Shared agents with elevated privileges       |
| `PLUGIN_TRUST_RISK`       | Dynamic plugin loading without isolation     |
| `WEAK_AGENT_ISOLATION`    | Weak workspace / agent isolation signals     |
| `WORKSPACE_PATH_RISK`     | Risky or overly broad workspace paths        |
| `NODE_COMMAND_SURFACE`    | Node/device command and control surfaces     |
| `TOKEN_STORAGE_RISK`      | Secrets or tokens in plaintext config        |
| `EXECUTION_SURFACE`       | Broad code execution capabilities            |
| `BROAD_FILESYSTEM_ACCESS` | Unrestricted filesystem access patterns      |
| `UNRESTRICTED_TOOLING`    | Tool access without approval gates           |
| `POTENTIAL_SECRET_IN_CONFIG` | Secret-like values in configuration       |

---

## Risk scoring

Findings are scored on a 0–100 scale and classified into bands:

| Score range | Band     |
|-------------|----------|
| 0 – 19     | Low      |
| 20 – 39    | Moderate |
| 40 – 69    | High     |
| 70 – 100   | Critical |

Each finding contributes a base severity score multiplied by a confidence factor. The total is clamped to the 0–100 range.

---

## Project structure

```
openclaw_audit/
├── cli.py            # CLI commands (typer)
├── config.py         # Scan configuration and defaults
├── models.py         # Typed data models
├── discovery.py      # File discovery and classification
├── loaders.py        # Safe file loading
├── scanner.py        # Scan orchestration
├── correlators.py    # Cross-file correlation logic
├── risk.py           # Risk scoring engine
├── parsers/          # Structured file parsers
├── rules/            # Detection rules by domain
├── reporting/        # Output formatters
├── utils/            # Shared helpers
└── rule_data/        # Default rule definitions
```

---

## Design philosophy

1. **Readability over cleverness** — every module is self-documenting.
2. **Modular rules** — add a new rule without touching the scanner.
3. **Graceful degradation** — malformed files are skipped, never crash.
4. **Static only** — no network, no deployment, no live interaction.
5. **Teachable** — written for classmates and future contributors.

---

## Adding a new rule

1. Create a file in `openclaw_audit/rules/` (e.g. `my_rules.py`).
2. Subclass `BaseRule` and implement `apply()`.
3. Register the rule in `openclaw_audit/rules/__init__.py`.
4. Add a test in `tests/`.

See existing rules for examples.

---

## Development

```bash
pip install -e ".[dev]"
pytest                  # Run tests
ruff check .            # Lint
ruff format .           # Format
mypy openclaw_audit     # Type-check
```

---

## License

MIT
