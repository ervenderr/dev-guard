---
phase: 04-n8n-alerting-readme
plan: 01
subsystem: cli
tags: [cli, exclude, walk]
requires: [03-02]
provides: [--exclude]
key-files:
  modified: [dev_guard/cli.py, dev_guard/checks.py, tests/test_cli.py]
requirements-completed: [ALERT-01]
metrics:
  completed: 2026-10-24
---

# Phase 4 Plan 1: --exclude flag Summary

Repeatable `--exclude PATH` skips a directory subtree by real path, so the cron wrapper can exclude dev-guard's own fixtures and a clean machine exits 0.

## Commits
- 37f1418 test: add failing --exclude cli tests (RED, 6 tests, failed on unrecognized argument)
- b9f12f5 feat: add repeatable --exclude flag (GREEN)

## Behaviour
- cli.py: `--exclude` (append); empty value exits 2 with "dev-guard: empty exclude path"; paths expanded and realpath'd, nonexistent ones ignored. `run_scan(..., exclude=())` passes through to `scan`.
- checks.py: `iter_files`/`scan` take `exclude`; scan root inside an excluded path yields nothing; excluded dirs pruned in the walk. realpath only computed when exclude is non-empty. Home config files are not affected.
- Existing stubs of `scan` already accepted `**kw`; stubs of `run_scan` take `*a, **k`. No test loosened.

## Verification
- Full suite: 503 passed (497 prior + 6 new).
- `python -m dev_guard --json --exclude tests/fixtures tests` -> no findings, exit 0.
- `python -m dev_guard --json tests/fixtures` still reports highs.

## Deviations
None.

## Self-Check: PASSED
