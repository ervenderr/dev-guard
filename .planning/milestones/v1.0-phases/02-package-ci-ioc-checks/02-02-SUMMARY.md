---
phase: 02-package-ci-ioc-checks
plan: 02
subsystem: checks
tags: [h4, github-workflows, oidc]
requires: [02-01]
provides: [check_workflow, H4 dispatch in target_for, H4 dir-symlink mapping]
affects: [02-03]
key-files:
  created: [tests/test_h4.py, tests/fixtures/h4/clean/.github/workflows/ci.yml, tests/fixtures/h4/malicious/.github/workflows/release.yaml]
  modified: [dev_guard/patterns.py, dev_guard/checks.py]
decisions:
  - "Line-based text scan, no YAML parser; run-block tracked by key indentation"
metrics:
  completed: 2026-10-23
  tasks: 2
requirements: [CI-01, CI-02]
---

# Phase 2 Plan 02: H4 GitHub workflow check Summary

Workflows under .github/workflows now yield findings for ACTIONS_ID_TOKEN_*, /proc/*/mem, unpinned actions, and H1 patterns inside run steps (inline and block scalars, CRLF-safe).

## Commits
- 8bef530 test: add failing H4 workflow tests
- 51ab5eb feat: detect workflow token theft and unpinned actions (H4)

## Verification
`.venv/bin/python -m pytest -q`: 313 passed (298 prior + 15 new). RED run: 10 failed, prior suite green.

## Deviations from Plan
None - plan executed exactly as written.

## Known Stubs
None.

## Self-Check: PASSED
