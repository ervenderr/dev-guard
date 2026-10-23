---
phase: 01-finding-model-safe-walking-hook-checks
fixed_at: 2026-10-23T00:00:00Z
review_path: .planning/phases/01-finding-model-safe-walking-hook-checks/01-REVIEW.md
iteration: 1
findings_in_scope: 9
fixed: 9
skipped: 0
status: all_fixed
---

# Phase 1: Code Review Fix Report

**Scope:** CR-01..03, WR-01..06 (Info skipped). Worked in place on master, no worktree.

## Fixed Issues

- **CR-01** (39f9402): oversize/unreadable target files now emit a low `oversize_file` / `unreadable_file` finding. `read_text` returns `(text, problem)`; `TARGETS` carries the check id.
- **CR-02** (6fe8aac): H1 scans `command` + `args` joined (shared `_high` with H2); dropped unused `collect_commands`. Logic fix: requires human verification.
- **CR-03** (cdfc8b0): regexes cover `| /bin/sh`, `| env bash`, `| xargs sh`, ksh/fish, `base64 -di`, `bash -c "$(python ...)"`, python/node network one-liners, `/dev/tcp`; new med `obfuscated_command` for `\x`, `''`, `""`, `$'`, `${`. Logic fix: requires human verification.
- **WR-01** (a1a3e47): `settings.local.json` in `TARGETS` and `HOME_CONFIG_FILES`.
- **WR-04** (73e7a9f): target lookup lowercased.
- **WR-02** (adacb32): symlinked target files/dirs yield med `symlinked_config`; never followed (also applies to home extra files).
- **WR-03** (e7ad0e5): `os.open(O_NOFOLLOW|O_NONBLOCK)` + `fstat` S_ISREG + bounded read; FIFOs reported as unreadable.
- **WR-06** (428dca8): `utf-8-sig` decode (BOM), `os.walk onerror` -> low `unreadable_dir` (check id `walk`), H1 raw-scan fallback on malformed JSON, dead `UnicodeDecodeError` catch removed.
- **WR-05** (2fa364e): lines split on `\n` only; `find_line` also tries `\/`-escaped variant. Not done: preferring the `"command"` key context for needle matches (kept simple); an unrelated earlier line containing the same string can still win.

## Skipped Issues

None.

## Notes

Existing tests deliberately updated: `test_oversize_skipped` and `test_unreadable_skipped` now expect low findings; `test_symlinked_file_skipped` now expects `symlinked_config`.

## Final pytest

```
........................................................................ [ 81%]
................                                                         [100%]
88 passed in 0.07s
```

_Fixer: Claude (gsd-code-fixer)_
