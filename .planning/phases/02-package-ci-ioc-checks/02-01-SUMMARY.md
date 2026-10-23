---
phase: 02-package-ci-ioc-checks
plan: 01
subsystem: checks
tags: [redos, regex, package-json, h3]
requires: []
provides: [linear-time H1_PATTERNS, MAX_LINE_LEN, PATTERN_OVERSIZE_LINE, target_for dispatch, check_package_json]
affects: [02-02, 02-03]
key-files:
  created: [tests/test_redos.py, tests/test_h3.py, tests/fixtures/h3/clean/package.json, tests/fixtures/h3/malicious/package.json]
  modified: [dev_guard/patterns.py, dev_guard/checks.py]
decisions:
  - "H1 regexes made linear with possessive path prefix and atomic first-keyword locks"
  - "scan dispatch via target_for(path) so H3-H5 can plug in"
metrics:
  completed: 2026-10-23
  tasks: 3
requirements: [PKG-01]
---

# Phase 2 Plan 01: Linear H1 regexes and H3 package.json check Summary

Fixed the quadratic ReDoS in the shared H1 regexes (also hardens H1/H2) and added H3 detection of malicious preinstall/install/postinstall scripts, including JSON too deep for `json.loads`.

## Commits
- 55ca1cb test: add failing H1 regex ReDoS timing tests
- 16f3b46 fix: make H1 regexes linear-time to prevent ReDoS
- d8c1c50 test: add failing H3 package.json lifecycle script tests
- 08360d7 feat: detect malicious package.json lifecycle scripts (H3)

## Verification
`.venv/bin/python -m pytest -q`: 298 passed (88 prior + 210 new). RED run confirmed 23 failures (timing hangs bounded at 10s, constants missing) before the fix.

## Deviations from Plan

**1. [Rule 1 - Bug] 5000-deep nesting does not raise RecursionError on Python 3.12**
- **Found during:** Task 3
- **Issue:** `json.loads` parses 5000 nested `[` fine; the RecursionError fallback was never exercised, so malformed_json assertions failed.
- **Fix:** tests use depth 100_000 (about 200 KB, under MAX_FILE_BYTES); 20000 is the observed threshold.
- **Files:** tests/test_h3.py, tests/test_redos.py

**2. [Rule 1 - Bug] Wrong expected line in my multiline-nesting test** (line 4, not 5). Test fixed.

Also: JSONDecodeError line numbers are used for malformed_json in check_package_json (plan said "one low finding"; line is more useful).

## Known Stubs
None.

## Self-Check: PASSED
