# Phase 2: Package, CI & IOC Checks - Context

**Gathered:** 2026-10-23
**Status:** Ready for planning

<domain>
## Phase Boundary

Install scripts, workflow steps, and known-bad lockfile entries are detected: H3, H4, H5 with tests; all five checks H1-H5 have clean + malicious fixtures.

</domain>

<decisions>
## Implementation Decisions

### H3 package.json scripts
- Reuse the H1 regexes in patterns.py on preinstall/install/postinstall; a match = high
- Lifecycle script with a non-allowlisted command = med
- Scan scripts only, not dependencies
- Line numbers via the existing find_line helper

### H4 workflows
- Text-scan .github/workflows/*.yml and *.yaml line by line; no YAML parser (stdlib only)
- `ACTIONS_ID_TOKEN_*` or `/proc/*/mem` = high
- `uses: owner/repo@ref` where ref is not a 40-hex SHA = med; actions/* counts as third-party too; skip local `./` and `docker://`
- H1 patterns in `run:` lines = high

### H5 IOC lockfiles
- iocs.json = {"npm": ["name@version"], "pypi": ["name==version"]}, hand-updated, seeded with clearly labelled placeholder entries
- package-lock.json parsed with json; pnpm-lock.yaml and requirements*.txt via line regex
- Exact name+version match only = high
- yarn.lock / poetry.lock out of scope
- Missing or malformed iocs.json = low finding, not a crash

### Claude's Discretion
Module layout within dev_guard/checks.py (split only if the file nears the size limit). Carry over Phase 1 review learnings: oversize/unreadable/symlinked target files report findings instead of skipping silently; match target filenames case-insensitively; keep findings free of matched text.

</decisions>

<code_context>
## Existing Code Insights

Phase 1 delivered Finding model, safe walker, H1/H2, patterns.py (H1 regexes, allowlist), 88 pytest tests, fixtures at tests/fixtures/<check>/{clean,malicious}, .venv with python3.12 + pytest.

</code_context>

<specifics>
## Specific Ideas

No specific requirements — open to standard approaches.

</specifics>

<deferred>
## Deferred Ideas

None.

</deferred>
