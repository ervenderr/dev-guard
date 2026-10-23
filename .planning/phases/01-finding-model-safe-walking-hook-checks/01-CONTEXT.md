# Phase 1: Finding Model, Safe Walking & Hook Checks - Context

**Gathered:** 2026-10-23
**Status:** Ready for planning

<domain>
## Phase Boundary

Malicious Claude and VS Code hooks are detected safely from a directory tree: Finding model, safe file walk, H1/H2 checks with tests.

</domain>

<decisions>
## Implementation Decisions

### Finding model & severity
- Finding is a frozen dataclass: check_id, severity, file, line, pattern name only
- Line numbers found by text-searching the raw file (json.load loses lines)
- H1 network fetch / base64 -d / eval / remote sh -c = high; command not in allowlist = med; malformed JSON = low
- Never store matched text, only the pattern name

### H1/H2 detection
- Walk hooks JSON recursively collecting `command` strings
- Allowlist in patterns.py = small prefix list of benign tools (prettier, eslint, git); anything else = med
- H2 `runOn: folderOpen` alone = med; folderOpen + H1 pattern = high
- H1 regexes live in patterns.py so H3 can reuse them in Phase 2

### Walking & fixtures
- os.walk pruning node_modules and .git; do not follow symlinks; skip files over 1 MB; unreadable file = skip silently
- Fixtures at tests/fixtures/<check>/{clean,malicious}; pytest, no dependencies
- `~/.claude/settings.json` scanned as an extra explicit file

### Claude's Discretion
Module internals beyond the SPEC layout (dev_guard/cli.py, checks.py, patterns.py).

</decisions>

<code_context>
## Existing Code Insights

Greenfield: no source code yet. Only SPEC.md and .planning/.

</code_context>

<specifics>
## Specific Ideas

No specific requirements — open to standard approaches.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>
