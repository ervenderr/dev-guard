---
phase: 01-finding-model-safe-walking-hook-checks
verified: 2026-10-23T00:00:00Z
status: passed
score: 5/5 must-haves verified
overrides_applied: 0
---

# Phase 1 Verification

**Goal:** Malicious Claude and VS Code hooks are detected safely from a directory tree.

| # | Success criterion | Status | Evidence |
|---|---|---|---|
| 1 | H1 on malicious settings.json gives high finding with file:line + pattern | VERIFIED | Independent scan: high network_fetch/remote_shell (line 9, 21), base64_decode (13), eval (17) |
| 2 | Non-allowlisted command yields finding; clean fixture yields none | VERIFIED | `node ~/.cache/updater.js` -> med not_in_allowlist line 25; clean h1/h2 fixtures -> `[]` |
| 3 | tasks.json folderOpen or H1-pattern command yields finding | VERIFIED | med run_on_folder_open (7, 13); high network_fetch/base64_decode/remote_shell |
| 4 | Malformed JSON -> low finding; >1MB, node_modules, .git skipped | VERIFIED | `{"hooks": [[[[` and 100k-deep `[` -> low malformed_json, no crash; 1.1MB file, node_modules/.git copies -> no findings |
| 5 | No secret values in output | VERIFIED | Finding has only check_id/severity/file/line/pattern; "FAKE_SECRET", "example.invalid" absent from scan output |

**Tests:** `.venv/bin/python -m pytest -q` -> 61 passed.
**Safety:** grep for exec/subprocess/os.system/eval( in dev_guard -> none (text is only parsed). Symlinks not followed.

## Requirements
CORE-01..05, HOOK-01..04 all satisfied by code/tests.

## Warnings (non-blocking)
- REQUIREMENTS.md checkboxes/traceability still show CORE-02, 03, 04 and HOOK-01 as Pending; implementation exists. Bookkeeping only.
- Non-allowlisted hook is severity med (spec says only "finding"); fine.
- Known documented shortcut: allowlist is prefix-match (`git`, `npx`), so `git -c alias...` passes. Acceptable for MVP.

## Gaps
None.
