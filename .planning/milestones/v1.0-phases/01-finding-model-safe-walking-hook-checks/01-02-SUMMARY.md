---
phase: 01-finding-model-safe-walking-hook-checks
plan: 02
subsystem: hook-checks
tags: [python, pytest, h1, h2, allowlist, jsonc]
requires: [01-01]
provides:
  - is_allowlisted, HOOK_ALLOWLIST, SHELL_CHAIN_RE (H1 med not_in_allowlist)
  - malformed_json low findings for H1 and H2 (JSONDecodeError, RecursionError, ValueError)
  - iter_command_dicts, command_parts, check_vscode_tasks (H2)
  - raw line-by-line fallback for JSONC tasks.json
key-files:
  created:
    - tests/test_h2.py
    - tests/fixtures/h2/clean/.vscode/tasks.json
    - tests/fixtures/h2/malicious/.vscode/tasks.json
  modified:
    - dev_guard/checks.py
    - dev_guard/patterns.py
    - tests/test_h1.py
    - tests/test_walk.py
    - tests/fixtures/h1/malicious/.claude/settings.json
key-decisions:
  - "HOOK-04: an H1 pattern in a .vscode task WITHOUT runOn folderOpen is still high (task can be run by hand or keybinding); folderOpen alone is med"
  - "is_allowlisted is prefix-based and known-weak for git -c alias / npx <pkg>; marked with a shortcut: comment"
requirements-completed: [HOOK-02, CORE-05, HOOK-03, HOOK-04, CORE-01]
metrics:
  tasks: 2
  completed: 2026-10-23
---

# Phase 1 Plan 02: Allowlist, malformed JSON, H2 tasks check Summary

H1 now flags non-allowlisted hooks (med) and unparseable settings (low); H2 flags folderOpen tasks (med) and H1 patterns in command/args/overrides/quoted-arg objects (high), with a raw-text fallback for JSONC.

## Commits

- 0e4e95d: test: add H1 allowlist and malformed JSON tests (RED)
- c2f4d1a: feat: add H1 allowlist and malformed JSON findings
- 8e93ad5: test: add H2 vscode tasks tests and fixtures (RED)
- 7cd4266: feat: add H2 vscode tasks check

## Verification

`.venv/bin/python -m pytest -q` -> `61 passed in 0.05s`. Clean fixtures scan to `[]`; scan of tests/fixtures yields check IDs `['H1', 'H2']`.

## Deviations from Plan

**1. [Rule 1 - Bug] Stale 01-01 test**
- `tests/test_walk.py::test_hostile_json_does_not_raise` asserted `[]` for hostile JSON; 01-01 explicitly deferred this to 01-02, which now returns one low `malformed_json`. Updated the assertion.
- Commit: c2f4d1a

## Known Stubs

None.

## Self-Check: PASSED
