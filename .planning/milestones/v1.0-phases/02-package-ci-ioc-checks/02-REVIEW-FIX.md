---
phase: 02-package-ci-ioc-checks
fixed_at: 2026-10-23T00:00:00Z
review_path: .planning/phases/02-package-ci-ioc-checks/02-REVIEW.md
iteration: 1
findings_in_scope: 8
fixed: 8
skipped: 0
status: all_fixed
---

# Phase 02: Code Review Fix Report

**Source review:** .planning/phases/02-package-ci-ioc-checks/02-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 8 (Info skipped)
- Fixed: 8
- Skipped: 0

Fixes were made directly in the main working tree (no worktree) at the caller's direction. Final suite: 465 passed.

## Fixed Issues

### CR-02: H4 `/proc/<pid>/mem` regex misses `$PID` and `${PID}`
**Files:** `dev_guard/patterns.py`, `tests/test_h4.py`
**Applied fix:** dropped `$` from the excluded class in `PROC_MEM_RE`. `cat /proc/cpuinfo > a/mem` stays unflagged. ReDoS timing tests pass.

### CR-01 and WR-06: line-length cap evaded H3/H4 content checks; duplicated H1 loop
**Files:** `dev_guard/checks.py`, `dev_guard/patterns.py`, tests
**Applied fix:** removed `MAX_LINE_LEN` and `oversize_line` entirely. Oversize lines and values are now regex-scanned, so H3, H4, H5 and the deep-JSON fallback all match their content. One `h1_findings()` helper replaces the four copies. Fixed: logic change, requires human verification.

### WR-01: oversize file only low
**Files:** `dev_guard/checks.py`, tests
**Applied fix:** `oversize_file` is now `med`. Other read problems stay `low`. Committed together with WR-03.

### WR-03: H3 lifecycle scripts too narrow
**Files:** `dev_guard/patterns.py`, `tests/test_h3.py`
**Applied fix:** added `prepare`, `prepublish`, `prepublishOnly`, `prepack`, `postpack` to `LIFECYCLE_SCRIPTS`.

### WR-02: H4 YAML run forms
**Files:** `dev_guard/patterns.py`, `dev_guard/checks.py`, tests
**Applied fix:** `RUN_KEY_RE` accepts quoted keys and flow-mapping `{run: ...}`. Any line indented deeper than a block `run:` key is scanned, which covers block, plain and quoted multi-line scalars. Removed `BLOCK_SCALAR_RE`. Fixed: logic change, requires human verification.

### WR-05: iocs.json handling
**Files:** `dev_guard/patterns.py`, `dev_guard/checks.py`, tests
**Applied fix:** bad entries are skipped and produce one low `iocs_malformed` finding. Good entries are kept. `DEV_GUARD_IOCS` env var overrides the path. `scan(iocs_path=...)` still wins. The default stays the repo-root `iocs.json`.

### WR-04: H5 pin forms and file discovery
**Files:** `dev_guard/patterns.py`, `dev_guard/checks.py`, `tests/test_h5.py`
**Applied fix:** accepts `===`, a leading `v`, and trailing `.0` segments (compared normalized on both sides). Backslash continuations are joined and the finding keeps the first line number. Discovery now covers `*-requirements*.txt` tokens, `requirements/*.txt` and `npm-shrinkwrap.json`. Fixed: logic change, requires human verification.

## Notes

WR-01 and WR-03 share one commit because the test edits overlap in `tests/test_h3.py`.

---

_Fixer: Claude (gsd-code-fixer)_
