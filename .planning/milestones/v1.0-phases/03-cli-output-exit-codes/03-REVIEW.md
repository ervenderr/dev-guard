---
phase: 03-cli-output-exit-codes
reviewed: 2026-10-24T00:00:00Z
depth: standard
files_reviewed: 7
files_reviewed_list:
  - dev_guard/cli.py
  - dev_guard/__main__.py
  - dev_guard/__init__.py
  - pyproject.toml
  - dev_guard/patterns.py
  - tests/test_cli.py
  - tests/test_cli_e2e.py
findings:
  critical: 2
  warning: 5
  info: 3
  total: 10
status: issues_found
---

# Phase 3: Code Review Report

**Reviewed:** 2026-10-24
**Depth:** standard
**Files Reviewed:** 7
**Status:** issues_found

## Summary

Phase 3 tests pass (25). Output safety is sound. `sanitize` plus `ensure_ascii` JSON neutralize hostile filenames. No matched text or exception text reaches stdout or stderr. Duplicate, nested and symlinked roots dedupe or scan correctly. `--` works.

The weak spot is exit-code discipline. Two paths produce a Python traceback with exit 1, which a CI gate reads as "high finding". The wheel also ships without `iocs.json`, so H5 is silently dead after a normal install. All probes below were run.

## Critical Issues

### CR-01: Uncaught exceptions in root validation and output exit 1 (the "high found" code)

**File:** `dev_guard/cli.py:80-90` (`_check_roots`), `dev_guard/cli.py:106-110` (output)
**Issue:** `_check_roots` runs outside the `try`. Confirmed:
- `dev-guard '~nouser_xyz'` hits `Path.expanduser()` and raises `RuntimeError: Could not determine home directory`. A traceback is printed and the exit code is 1.
- `dev-guard <dir under a chmod 000 parent>` makes `Path.exists()` raise `PermissionError`. The result is a traceback and exit 1.
- Closed stdout (`>&-`) raises `AttributeError` on `sys.stdout.write` (stdout is None). Exit 1, traceback.
- A write failure such as ENOSPC or EIO raises `OSError`. It is not mapped, so the result is the same.

The contract is that 1 means high only, 2 means usage, and 70 means internal. A failed scan that looks like a high finding is a fail-open/fail-wrong gate. The tracebacks also embed full paths.
**Fix:**
```python
def _check_roots(paths):
    roots = []
    for p in paths:
        try:
            path = Path(p).expanduser()
            exists, is_dir = path.exists(), path.is_dir()
        except (OSError, RuntimeError):
            return [], f"dev-guard: {sanitize(p)}: cannot access"
        ...
# output block
    try:
        sys.stdout.write(text + "\n"); sys.stdout.flush()
    except BrokenPipeError:
        ...
    except (OSError, AttributeError) as exc:
        sys.stderr.write(f"dev-guard: output error: {type(exc).__name__}\n")
        return EXIT_INTERNAL
```
Alternatively, wrap all of `main` after `parse_args` in the same `except Exception` that returns 70.

### CR-02: Wheel omits `iocs.json`, so H5 is disabled for any non-editable install

**File:** `pyproject.toml:14-15`, `dev_guard/patterns.py:90`
**Issue:** `packages = ["dev_guard"]` has no package data. `IOCS_PATH` is `Path(__file__).parent.parent / "iocs.json"`. I built a wheel (`pip wheel .`) and it contains only the 4 `.py` files and no `iocs.json`. An installed `dev-guard` resolves to `site-packages/iocs.json`, which does not exist. Every scan then yields a `low` `iocs_missing`, and exit stays 0 even if a compromised package is present. The e2e tests run from the repo root, so they never see this. This is the open Phase 2 WR-05 packaging half, now reachable via the console script added in this phase.
**Fix:** Move the file to `dev_guard/iocs.json`. Set `IOCS_PATH = Path(__file__).resolve().parent / "iocs.json"`. In `pyproject.toml`, add `[tool.setuptools.package-data] dev_guard = ["iocs.json"]`. Add a test that builds a wheel or checks `importlib.resources`. Also treat a missing IOC file as `med` or higher.

## Warnings

### WR-01: Empty-string path silently scans the current directory

**File:** `dev_guard/cli.py:83`
**Issue:** `dev-guard ""` gives `Path("")`, which is `.`. It exists, so it passes validation and scans the cwd. An unset shell variable (`dev-guard "$DIR"`) is a typical way to hit this. The scan reports on the wrong tree, and the user may believe the target was clean.
**Fix:** Reject empty strings: `if not p: return [], "dev-guard: empty path"` (exit 2).

### WR-02: argparse errors echo raw argv to stderr, so terminal escapes pass through

**File:** `dev_guard/cli.py:28-33`
**Issue:** `dev-guard $'--bad\x1b[31mX'` prints `unrecognized arguments: --bad^[[31mX`, a raw ESC on stderr. This breaks the sanitize guarantee the rest of the file enforces for hostile names. The practical risk is low, since the args are user-supplied.
**Fix:** Subclass `ArgumentParser` and override `error()` to pass the message through `sanitize` before `self.exit(EXIT_USAGE, ...)`.

### WR-03: `test_broken_pipe` can pass vacuously

**File:** `tests/test_cli.py:127-138`
**Issue:** The parent closes `proc.stdout` right after `Popen`. If the child finishes the scan and writes before the close, the write lands in the pipe buffer and no `BrokenPipeError` ever happens. The test passes anyway, because it only asserts exit 1 and no traceback. Across the scan time and the close race, the test is non-deterministic and may not exercise the handler. Output is also small, so it is not guaranteed to overflow.
**Fix:** Test deterministically in-process: monkeypatch `sys.stdout` with an object whose `write` raises `BrokenPipeError` (plus a real `fileno()`), and assert the return code and that `os.dup2` was called. Or have the child block on stdin before writing.

### WR-04: Wall-clock perf test is flaky on slow or loaded machines

**File:** `tests/test_cli_e2e.py:11,89-98`
**Issue:** `test_perf_5k_files` asserts `< 5.0s` on a 5000-file tree. The tree creation is excluded from the timing, but the scan time depends on disk, antivirus and CI load. The budget is a fixed constant with no headroom control. Elapsed time on a cold cache (macOS tmp) can spike.
**Fix:** Mark it `@pytest.mark.perf` and skip it by default, or measure scan time relative to a baseline `os.walk` of the same tree. Alternatively, raise the budget to match the real constraint (30s for `~/Projects`).

### WR-05: Overlapping roots spelled differently produce duplicate rows

**File:** `dev_guard/cli.py:41-49`
**Issue:** The dedupe set keys on `Finding`, which includes `str(path)`. `real`, `real/` and `./real` collapse because `Path` normalizes them. But `real` and `real/../real`, or a symlink `link` and `real`, do not. Probed: scanning a symlinked root gives `link/...` paths, so passing both `link` and `real` reports the same file twice and inflates the summary counts. The `seen` realpath dedupe in `scan()` is per call.
**Fix:** Dedupe roots by `os.path.realpath` before scanning, or drop roots that are nested inside an earlier root.

## Info

### IN-01: Internal error discards all diagnostic context

**File:** `dev_guard/cli.py:103-105`
**Issue:** Only `type(exc).__name__` is printed. The choice not to leak text is right, but the user has no way to debug a 70. One broad `except Exception` also covers `format_*`.
**Fix:** Add an opt-in `DEV_GUARD_DEBUG=1` that prints the traceback with `traceback.print_exc()`. Alternatively, print the failing function name and the exception's file and line, which carry no content.

### IN-02: `os.dup2` fd leak and unguarded in the BrokenPipe handler

**File:** `dev_guard/cli.py:109-110`
**Issue:** The `os.open` result is never closed. This is harmless at process exit, but `main()` can be called many times in tests. If `sys.stdout.fileno()` raises (replaced stdout), the handler itself raises.
**Fix:** `fd = os.open(os.devnull, os.O_WRONLY); try: os.dup2(fd, sys.stdout.fileno()) finally: os.close(fd)`.

### IN-03: e2e tests hardcode `cwd=REPO_ROOT` and use `-m dev_guard`

**File:** `tests/test_cli_e2e.py:16-21`
**Issue:** The subprocess tests only prove the package works from the source tree. They do not cover the console-script and installed-package path (see CR-02).
**Fix:** Add one test that installs into a temp venv or runs the `dev-guard` entry point from a different cwd.

---

_Reviewed: 2026-10-24_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
