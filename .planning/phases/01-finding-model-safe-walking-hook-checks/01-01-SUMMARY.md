---
phase: 01-finding-model-safe-walking-hook-checks
plan: 01
subsystem: scanner-core
tags: [python, pytest, h1, walker, finding]
requires: []
provides:
  - Finding frozen dataclass
  - iter_files safe walker, read_text, collect_commands, find_line
  - check_claude_settings (H1 high detection)
  - scan(root, extra_files) dispatch
  - patterns.py constants (H1_PATTERNS, SKIP_DIRS, MAX_FILE_BYTES, HOME_CONFIG_FILES)
affects: [01-02, phase-2, phase-3]
tech-stack:
  added: [pytest (dev-only, .venv)]
  patterns: [dispatch table keyed on (parent_dir, filename), constants-only patterns module]
key-files:
  created:
    - .gitignore
    - pyproject.toml
    - dev_guard/__init__.py
    - dev_guard/patterns.py
    - dev_guard/checks.py
    - tests/fixtures/h1/clean/.claude/settings.json
    - tests/fixtures/h1/malicious/.claude/settings.json
    - tests/test_h1.py
    - tests/test_walk.py
    - tests/test_safety.py
key-decisions:
  - "Hostile JSON (deep nesting, huge int) returns no findings for now; malformed_json reporting is left to 01-02"
metrics:
  tasks: 2
  files: 10
  completed: 2026-10-23
---

# Phase 1 Plan 01: Walking skeleton Summary

Safe walker plus H1 high detection on `.claude/settings.json`, driven end-to-end by `scan()`, with 31 passing tests.

## Commits

- c31f97a: test: add failing H1 skeleton tests and fixtures (RED, collection failed on missing dev_guard.checks)
- a7750ce: feat: add Finding model, safe walker and H1 hook detection (GREEN)

## Verification

`.venv/bin/python -m pytest -q` -> `31 passed in 0.02s`.
Malicious fixture high patterns: `['base64_decode', 'eval', 'network_fetch', 'remote_shell']`; clean fixture has no high findings.

## Deviations from Plan

None. Commits carry no attribution lines, per the orchestrator and user instructions.

## Known Stubs

None. `check_claude_settings` returns `[]` for malformed/hostile JSON by design (01-02 adds the low finding).

## Self-Check: PASSED
