---
phase: 03-cli-output-exit-codes
fixed_at: 2026-10-24T00:00:00Z
review_path: .planning/phases/03-cli-output-exit-codes/03-REVIEW.md
iteration: 1
findings_in_scope: 7
fixed: 7
skipped: 0
status: all_fixed
---

# Phase 3: Code Review Fix Report

**Source review:** 03-REVIEW.md (Critical + Warning only; Info skipped)
**Full suite after fixes:** 497 passed

## Fixed Issues

### CR-01: Uncaught exceptions exit 1
**Files:** `dev_guard/cli.py`, `tests/test_cli.py`
Unreadable or unresolvable roots (`~nouser`, `PermissionError`) now exit 2 with "cannot access". Output write failures (`OSError`, closed stdout) exit 70 and print only the exception type. Requires human verification (exit-code logic).

### CR-02: Wheel omits iocs.json
**Files:** `dev_guard/iocs.json` (moved from repo root), `dev_guard/patterns.py`, `pyproject.toml`, `tests/test_h5.py`
`IOCS_PATH` now points inside the package, and package-data includes it. A built wheel contains `dev_guard/iocs.json`. The `DEV_GUARD_IOCS` override is unchanged. The review's optional "missing IOC file should be med" was not applied (it would change severity semantics and existing tests).

### WR-01: Empty path scanned cwd
`cli.py`: an empty string now exits 2 ("empty path"). Requires human verification.

### WR-02: argparse echoed raw argv
`cli.py`: `_Parser.error` sanitizes the message and exits 2.

### WR-03: Vacuous broken-pipe test
`tests/test_cli.py`: now in-process with a stdout stub that raises `BrokenPipeError`. It asserts `dup2` is called on the stub's fd and the exit code is 1.

### WR-04: Flaky perf test
`tests/test_cli_e2e.py`: budget raised from 5s to the 30s spec constraint.

### WR-05: Overlapping roots duplicated rows
`cli.py` `run_scan`: roots are deduped by `os.path.realpath` (first spelling wins). Requires human verification.

---

_Fixer: Claude (gsd-code-fixer)_
