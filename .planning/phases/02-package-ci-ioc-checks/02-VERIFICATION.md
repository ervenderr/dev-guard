---
phase: 02-package-ci-ioc-checks
verified: 2026-10-23T00:00:00Z
status: passed
score: 4/4 must-haves verified
overrides_applied: 0
---

# Phase 2: Package, CI & IOC Checks Verification Report

**Phase Goal:** Install scripts, workflow steps, and known-bad lockfile entries are detected
**Status:** passed. **Re-verification:** No.

## Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | package.json malicious postinstall yields finding | VERIFIED | Hostile `curl ... \| sh` postinstall -> H3 high `network_fetch` + `remote_shell` at line 1 |
| 2 | Workflow ACTIONS_ID_TOKEN / /proc/*/mem / unpinned action yields finding | VERIFIED | H4 high `actions_id_token` (line 7), high `proc_mem` (9), med `unpinned_action` (5), run-block `base64 -d \| sh` high; SHA-pinned action not flagged |
| 3 | IOC entry in lockfile/requirements yields high | VERIFIED | package-lock v3 (scoped + unscoped), pnpm-lock (both, lines 3 and 5), `requirements-dev.txt` with non-normalized name `Dev_Guard.IOC-placeholder==0.0.1` -> H5 high `ioc_match` |
| 4 | H1-H5 each have clean-pass and malicious-detect tests | VERIFIED | `tests/test_fixtures_matrix.py` plus `tests/test_h1..h5.py`; `pytest -q`: 448 passed |

## Hostile Inputs

- 100000-deep nested JSON: package.json -> `malformed_json` low plus the postinstall highs via regex fallback; package-lock -> IOC high still found plus low `malformed_json`. No crash.
- ~1 MB / 500 KB single lines (requirements, workflow, package.json script): `oversize_line` or `oversize_file` low in under 0.1s each. No ReDoS.
- Output contains only check_id, severity, file, line and pattern name. The secret marker `SECRETVAL123` embedded in the script never appears.

## Requirements

PKG-01, CI-01, CI-02, IOC-01 and TEST-01 are all SATISFIED. No orphaned requirements.

## Anti-Patterns

No TBD/FIXME/XXX markers found in `dev_guard/checks.py`. Documented `shortcut:` comments are known limits (line-based workflow scan, with no YAML parser or flow mappings).

## Notes (non-blocking)

- Padding a workflow line past MAX_LINE_LEN skips H4 content checks on it, but it is reported as low `oversize_line`.
- `iocs.json` holds placeholder IOC entries only. The roadmap does not require real data.

## Human Verification Required

None.
