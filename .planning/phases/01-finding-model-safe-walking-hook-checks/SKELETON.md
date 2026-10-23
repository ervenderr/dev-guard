# Walking Skeleton — dev-guard

**Phase:** 1
**Generated:** 2026-10-23

## Capability Proven End-to-End

`scan(tmp_root)` walks a real directory tree, safely skips `node_modules`/`.git`/symlinks/oversized files, parses `.claude/settings.json`, and returns a high `Finding` (check_id `H1`, file, line, pattern name; never the matched text) for a `curl ... | sh` hook in the H1 malicious fixture. A pytest test drives this.

## Architectural Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Language / runtime | Python 3.12 (`/opt/homebrew/bin/python3.12`), stdlib only | SPEC stack lock; no dependencies |
| Test runner | pytest, installed only into a local `.venv` (dev-only) | SPEC; runtime stays dependency-free |
| Packaging | Minimal `pyproject.toml` with only `[tool.pytest.ini_options]` (`pythonpath = ["."]`, `testpaths = ["tests"]`) | Tests import `dev_guard` without install. Phase 3 adds `[project]` + console script |
| Module layout | `dev_guard/{__init__,checks,patterns}.py`; `cli.py` arrives in Phase 3 | SPEC layout. No extra modules |
| Finding model | Frozen dataclass `Finding(check_id, severity, file, line, pattern)` in `dev_guard/checks.py` | CONTEXT decision; there is no field that can hold matched text, so secrets can't leak |
| Constants | Every regex, the allowlist, severities, pattern names, skip dirs, size cap, and home config paths live in `dev_guard/patterns.py` | User rule: no hardcoded values; H3 (Phase 2) reuses `H1_PATTERNS` |
| Check contract | Each check is `check_x(path: Path, text: str) -> list[Finding]`; `scan(root, extra_files)` dispatches by `(parent_dir_name, file_name)` | One entry point for the CLI (Phase 3) and new checks (Phase 2) |
| File walking | `os.walk(followlinks=False)`, pruning `SKIP_DIRS` in place; skip symlinked files, files over `MAX_FILE_BYTES`, and unreadable files | CORE-04 plus symlink-traversal threat |
| Line numbers | Search the raw text for the JSON-escaped command string; fall back to line 1 | `json.loads` drops line info (CONTEXT) |
| Fixtures | `tests/fixtures/<check>/{clean,malicious}/...`; walker edge cases built in pytest `tmp_path` | CONTEXT decision; keeps `node_modules`/symlinks/1 MB files out of git |
| Database / UI / auth / deployment | None | Local read-only CLI. No DB, no web UI, no auth, nothing deployed. The local run command is `.venv/bin/python -m pytest -q` |

## Stack Touched in Phase 1

- [x] Project scaffold: venv, pytest config, `.gitignore`, package
- [x] Routing equivalent: `scan()` dispatches files to checks
- [ ] Database: not applicable (no persistence)
- [ ] UI: not applicable in Phase 1 (terminal table/JSON comes in Phase 3)
- [x] Local full-stack run: `.venv/bin/python -m pytest -q`

## Out of Scope (Deferred to Later Slices)

- H3 `package.json` scripts, H4 workflows, H5 lockfiles/`iocs.json` (Phase 2)
- argparse CLI, table/`--json` output, exit codes, `~/Projects` default root, perf budget (Phase 3)
- cron + n8n alerting, README (Phase 4)
- YAML parsing, obfuscation-resistant detection, Linux/Windows paths (v2 / out of scope)

## Subsequent Slice Plan

- Phase 2: add `check_package_json`, `check_workflow`, `check_lockfile` behind the same `scan()` dispatch, reusing `H1_PATTERNS`
- Phase 3: `dev_guard/cli.py` calls `scan(root, HOME_CONFIG_FILES)` and renders findings; exit 1 on any high
- Phase 4: cron runs `dev-guard --json`, POSTs findings to n8n
