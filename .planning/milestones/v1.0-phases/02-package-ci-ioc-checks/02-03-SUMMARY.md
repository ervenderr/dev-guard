---
phase: 02-package-ci-ioc-checks
plan: 03
subsystem: checks
tags: [h5, iocs, lockfile, test-matrix]
requires: [02-02]
provides: [iocs.json, load_iocs, check_lockfile, H5 dispatch, scan iocs_path, TEST-01 matrix]
affects: [phase-3]
key-files:
  created: [iocs.json, tests/test_h5.py, tests/test_fixtures_matrix.py, tests/fixtures/h5/clean/package-lock.json, tests/fixtures/h5/clean/requirements.txt, tests/fixtures/h5/malicious/package-lock.json, tests/fixtures/h5/malicious/pnpm-lock.yaml, tests/fixtures/h5/malicious/requirements-dev.txt]
  modified: [dev_guard/patterns.py, dev_guard/checks.py, tests/test_redos.py, .planning/REQUIREMENTS.md]
decisions:
  - "package-lock walk uses an explicit stack for v1 dependencies, so no recursion limit applies after a successful parse"
  - "RecursionError lockfiles fall back to a linear whole-text LOCK_ENTRY_RE scan (offset-derived line), so minified deep files still yield high"
  - "iocs.json problems are one low H5 finding per scan, never a crash"
metrics:
  completed: 2026-10-23
  tasks: 3
requirements: [IOC-01, TEST-01]
---

# Phase 2 Plan 03: H5 IOC lockfile matching and TEST-01 matrix Summary

Entries in package-lock.json (v1/v2/v3, key name, `name` field and `npm:` aliases), pnpm-lock.yaml and requirements*.txt that match `iocs.json` yield high H5 findings; one parametrized test now proves clean and malicious fixtures for H1-H5.

## Commits
- 0312695 test: add failing H5 IOC lockfile tests
- 60fdfe1 feat: match lockfile entries against iocs.json (H5)
- c6b0786 test: enforce clean and malicious fixtures for every check (TEST-01)

## Verification
`.venv/bin/python -m pytest -q`: 448 passed (313 prior + 135 new). RED run: 24 failed, prior suite green. Verification one-liner prints `['H1', 'H2', 'H3', 'H4', 'H5']`.

## Deviations from Plan

**1. [Rule 1 - Bug] Plan said 5000-deep nesting; used 100_000** (5000 does not raise RecursionError on Python 3.12), as in 02-01.

**2. Extra timing tests (requested):** test_redos.py also times LOCK_ENTRY_RE on four hostile shapes and the H4 PROC_MEM/USES/RUN/OIDC/BLOCK_SCALAR plus pnpm/requirements regexes on ~1 MB repeated-unit lines (all under 1s). Closes the gap left by 02-02.

**3. Test expectation fix:** `test_iocs_without_pypi_key` expects 3 highs (scoped pnpm key is not in that iocs list), corrected during GREEN.

Also: v2 lockfiles list each package under both `packages` and `dependencies`; findings are de-duplicated per line.

## Known Stubs
iocs.json holds fake labelled placeholder entries by design (`_comment` says so); real intel is hand-maintained (T-02-14 accepted).

## Self-Check: PASSED
