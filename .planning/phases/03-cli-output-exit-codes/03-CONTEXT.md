# Phase 3: CLI Output & Exit Codes - Context

**Gathered:** 2026-10-24
**Status:** Ready for planning

<domain>
## Phase Boundary

User runs `dev-guard` and gets readable results and a usable exit code: default scan, table and JSON output, exit codes, performance (CLI-01..05, TEST-02). Implements dev_guard/cli.py per SPEC layout.

</domain>

<decisions>
## Implementation Decisions

### Invocation & scan roots
- Console script `dev-guard` via pyproject [project.scripts], plus `python -m dev_guard`
- No args = scan ~/Projects plus ~-level config files (~/.claude/settings.json, ~/.claude/settings.local.json)
- Positional PATH(s) override the default roots
- Nonexistent path = message to stderr, exit 2
- No flags beyond `--json` and `--version`

### Output & exit codes
- Table columns: SEV | ID | FILE:LINE | PATTERN, sorted high > med > low then path; plain str.ljust alignment, no color
- Summary line `N high, N med, N low`; clean scan prints `No findings.`
- `--json` prints {"findings":[{check_id,severity,file,line,pattern}],"summary":{high,med,low}} to stdout and nothing else
- Exit 1 if any high finding, 0 otherwise, 2 for usage errors
- Output never contains matched text, only pattern names

### Performance & tests
- CLI-05 measured by a timed run on the real ~/Projects, recorded in the phase SUMMARY, plus a synthetic 5k-file tree test asserting under 5s
- TEST-02: main()/subprocess tests: clean fixture tree exits 0; tests/fixtures tree exits 1 with expected IDs H1-H5
- No-secrets-in-output asserted with a planted marker
- If the real scan exceeds 30s, optimize the walk; do not raise the budget

### Claude's Discretion
Module internals of cli.py; how the default roots are expressed as constants.

</decisions>

<code_context>
## Existing Code Insights

scan(root, extra_files, iocs_path) (single root; CLI must call per root and dedupe; HOME_CONFIG_FILES is the default extra_files) in dev_guard/checks.py returns list[Finding]; Finding is a frozen dataclass (check_id, severity, file, line, pattern). 465 pytest tests; .venv python3.12. iocs.json at repo root, overridable via DEV_GUARD_IOCS env or scan(iocs_path=...). pyproject.toml exists from Phase 1.

</code_context>

<specifics>
## Specific Ideas

No specific requirements — open to standard approaches.

</specifics>

<deferred>
## Deferred Ideas

None.

</deferred>
