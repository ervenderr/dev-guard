---
phase: 03-cli-output-exit-codes
verified: 2026-10-24T00:00:00Z
status: passed
score: 5/5 must-haves verified
overrides_applied: 0
---

# Phase 3: CLI Output & Exit Codes Verification Report

**Phase Goal:** User runs `dev-guard` and gets readable results and a usable exit code
**Status:** passed
**Re-verification:** No

## Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | No args scans ~/Projects + ~ config files; `dev-guard <path>` scans path | VERIFIED | cli.py `main` uses DEFAULT_SCAN_ROOTS + HOME_CONFIG_FILES when no paths; no-arg run scanned real tree (195+ findings); explicit path runs worked |
| 2 | Table with severity, check ID, file:line, pattern | VERIFIED | Fixture run prints `SEV \| ID \| FILE:LINE \| PATTERN` rows + summary line |
| 3 | `--json` prints valid JSON | VERIFIED | stdout parses as a single JSON doc (`findings`, `summary`); stderr empty |
| 4 | Exit 1 on high, 0 clean; fixtures exit 1 with expected IDs | VERIFIED | clean tmp tree rc=0 "No findings."; tests/fixtures rc=1, IDs H1-H5 all present (23 high, 7 med) |
| 5 | ~/Projects scan < 30s | VERIFIED | Real no-arg scan: 15.1s wall (rc=1). Counts only recorded. |

**Score:** 5/5

## Behavioral Spot-Checks

| Behavior | Result | Status |
|----------|--------|--------|
| `pytest -q` | 490 passed in 25.7s | PASS |
| `.venv/bin/dev-guard` and `python -m dev_guard` | same behavior, rc=1 on malicious tree | PASS |
| `--version` (both entry points) | `dev-guard 0.1.0` | PASS |
| `/nonexistent` (table and --json) | stderr message, rc=2, nothing on stdout | PASS |
| Hostile dir name with ESC + newline | table shows `\x1b[31m` and `\n` escaped (cat -v clean); JSON ASCII-escaped | PASS |
| Secret/matched text in output | Only file:line + pattern name; hook command text (`curl ...`, host) absent from JSON | PASS |

## Requirements Coverage

CLI-01..05 and TEST-02: SATISFIED (see truths; TEST-02 covered by tests/test_cli_e2e.py, passing). No orphaned requirements.

## Anti-Patterns

None found in dev_guard/cli.py (no TODO/FIXME/stubs). Internal errors print type name only.

## Human Verification Required

None.

## Gaps Summary

No gaps. Note: timing is machine- and tree-dependent (15s vs 30s budget leaves ~2x headroom).

_Verifier: Claude (gsd-verifier)_
