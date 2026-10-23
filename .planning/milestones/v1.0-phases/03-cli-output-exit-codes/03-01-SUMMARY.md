---
phase: 03-cli-output-exit-codes
plan: 01
subsystem: cli
tags: [cli, argparse, exit-codes, packaging]
requires: []
provides: [dev_guard.cli.main, dev-guard console script, python -m dev_guard]
affects: [03-02, phase-4-docs]
key-files:
  created: [dev_guard/cli.py, dev_guard/__main__.py, tests/test_cli.py]
  modified: [dev_guard/patterns.py, dev_guard/__init__.py, pyproject.toml, .gitignore]
requirements-completed: [CLI-01, CLI-02, CLI-04]
metrics:
  completed: 2026-10-24
---

# Phase 3 Plan 1: CLI table output and exit codes Summary

`dev-guard PATH...` / `python -m dev_guard PATH...` prints a sanitized, sorted SEV | ID | FILE:LINE | PATTERN table plus summary, with exit codes 0 clean, 1 high, 2 usage, 70 internal error.

## Commits
- cc8b1fe test: add failing cli table and exit code tests (RED)
- ef1413f feat: add dev-guard cli table output and exit codes (GREEN)
- chore: package dev-guard console script and module entry point

## Verification
- Full suite: 478 passed (465 prior + 13 new).
- Console script: VERIFIED. `pip install -e .` succeeded; `.venv/bin/dev-guard` on h1/malicious exits 1, `/nonexistent` exits 2, h1/clean prints `No findings.` and exits 0.
- Broken pipe subprocess test passes (exit 1, no traceback); internal error test passes (exit 70, type name only).

## Deviations
1. [Rule 3] `dev_guard/__main__.py` was created in Task 1's commit instead of Task 2, because the broken-pipe test needs `python -m dev_guard`.
2. [Rule 1] The existing AST gate in tests/test_safety.py bans `print` in `dev_guard/*.py`, so cli.py writes with `sys.stdout.write` / `sys.stderr.write` instead of `print`. Gate left unchanged.

## Handoff
- Phase 4 (DOC-01): README must document exit codes 0/1/2/70.
- 03-02: default roots replace the empty `paths` case; `__version__ = "0.1.0"` exists for `--version`; `run_scan` takes `extra_files` for the home config files.

## Known Stubs
None.

## Self-Check: PASSED
