---
phase: 03-cli-output-exit-codes
plan: 02
subsystem: cli
tags: [cli, json, version, default-roots, e2e, perf]
requires: [03-01]
provides: [--json, --version, DEFAULT_SCAN_ROOTS, tests/test_cli_e2e.py]
key-files:
  created: [tests/test_cli_e2e.py]
  modified: [dev_guard/cli.py, dev_guard/patterns.py, tests/test_cli.py, .planning/REQUIREMENTS.md]
requirements-completed: [CLI-01, CLI-03, CLI-05, TEST-02]
metrics:
  completed: 2026-10-24
---

# Phase 3 Plan 2: --json, --version, default roots, e2e tests Summary

`dev-guard` with no args scans `~/Projects` plus the home Claude settings files; `--json` prints pure-ASCII JSON (`findings` + `summary`), `--version` prints `dev-guard 0.1.0`, and subprocess e2e tests cover exit codes, no-secret output and a 5k-file perf budget.

## Commits
- test: add failing json, version and default-root cli tests (RED)
- feat: add --json, --version and default scan roots (GREEN)
- test: add end-to-end exit code, no-secret and perf tests
- docs: mark phase 3 cli requirements complete

## Verification
- Full suite: 490 passed (478 prior + 8 cli + 4 e2e).
- Hostile filename JSON round-trips; table output has no raw ESC.
- DGSECRET_ marker planted in H1-H5 fixtures (incl. H4 run line, H5 lockfile root name, requirements comment) never appears in table or JSON stdout/stderr.

## Real scan (CLI-05)
- `dev-guard --json` on default roots: 14.93s wall (budget 30s). checks.py untouched.
- Counts: 26 high, 169 med, 1 low.
- 23 of 26 highs come from dev-guard's own tests/fixtures.
- Table mode (no args) exit code 1, same as JSON run.

## Handoff to Phase 4
- (a) ~/Projects contains dev-guard's own malicious fixtures, so a default `dev-guard` run always exits 1 (measured: 26 highs, 23 from tests/fixtures).
- (b) Phase 4 cron/n8n alerting must account for this (e.g. alert only on new highs, or decide where dev-guard lives); that decision belongs to Phase 4 discussion. No flag, exclude list or config was added (CONTEXT locks flags to `--json` and `--version`).
- (c) README (DOC-01) must document exit codes 0/1/2/70.

## Deviations
None. Note: cli.py uses `sys.stdout.write` (AST gate bans print).

## Known Stubs
None.

## Self-Check: PASSED
