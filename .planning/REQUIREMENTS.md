# Requirements: dev-guard

## v1 Requirements

### Core Model & Safety
- [ ] **CORE-01**: Every check returns `list[Finding]` with severity (high/med/low), check ID, file, line, matched pattern
- [ ] **CORE-02**: Scanner never prints secret values; output shows only file:line and matched pattern name
- [ ] **CORE-03**: Scanner only parses file text and never executes scanned content
- [ ] **CORE-04**: Directory walk skips `node_modules` and `.git` and skips files over 1 MB
- [ ] **CORE-05**: Malformed JSON is reported as a low finding instead of crashing the scan

### Hook Checks
- [ ] **HOOK-01**: User sees a high finding for `.claude/settings.json` (project and `~/.claude`) hooks that run `curl`/`wget`/`nc`, `base64 -d`, `eval`, or remote `sh -c`
- [ ] **HOOK-02**: User sees a finding for `.claude/settings.json` hook commands not in the allowlist in `patterns.py`
- [ ] **HOOK-03**: User sees a finding for `.vscode/tasks.json` tasks with `runOn: folderOpen`
- [ ] **HOOK-04**: User sees a finding for `.vscode/tasks.json` task commands matching the H1 patterns

### Package & CI Checks
- [ ] **PKG-01**: User sees a finding for `package.json` `preinstall`/`install`/`postinstall` scripts matching H1 patterns
- [ ] **CI-01**: User sees a finding for `.github/workflows/*.yml` steps echoing or reading `ACTIONS_ID_TOKEN_*` or `/proc/*/mem`
- [ ] **CI-02**: User sees a finding for third-party actions not pinned to a SHA
- [ ] **IOC-01**: User sees a high finding when a `package-lock.json`, `pnpm-lock.yaml`, or `requirements*.txt` entry matches a package@version in `iocs.json`

### CLI & Output
- [ ] **CLI-01**: `dev-guard` scans `~/Projects` plus `~`-level config files by default and accepts an explicit path
- [ ] **CLI-02**: Findings print as a terminal table (severity, check ID, file:line, pattern)
- [ ] **CLI-03**: `--json` outputs findings as machine-readable JSON
- [ ] **CLI-04**: Exit code is 1 if any high finding, else 0
- [ ] **CLI-05**: Scan of `~/Projects` completes in under 30s

### Tests & Docs
- [ ] **TEST-01**: Each check H1–H5 has a failing test on a malicious fixture and a passing test on a clean fixture
- [ ] **TEST-02**: Scan of a clean repo exits 0; scan of the fixtures exits 1 with the expected IDs
- [ ] **DOC-01**: README documents install, usage, and the n8n webhook flow

### n8n Alerting (Phase 2)
- [ ] **ALERT-01**: A cron entry runs `dev-guard --json` on a schedule
- [ ] **ALERT-02**: Findings are POSTed to an n8n webhook (findings only, never file contents)
- [ ] **ALERT-03**: n8n notifies via Telegram/email only on new high findings

## v2 Requirements

- Linux/Windows path support
- Live advisory feed for IOCs
- Obfuscation-resistant detection

## Out of Scope

| Feature | Reason |
|---------|--------|
| Auto-remediation / deletion | Read-only by design |
| Malware sandboxing | Not a pattern-scanner job |
| Windows/Linux paths | macOS first |
| Web dashboard | Terminal + n8n alerts suffice |
| Live advisory feeds | v1 uses static `iocs.json` |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| CORE-01 | Phase 1 | Pending |
| CORE-02 | Phase 1 | Pending |
| CORE-03 | Phase 1 | Pending |
| CORE-04 | Phase 1 | Pending |
| CORE-05 | Phase 1 | Pending |
| HOOK-01 | Phase 1 | Pending |
| HOOK-02 | Phase 1 | Pending |
| HOOK-03 | Phase 1 | Pending |
| HOOK-04 | Phase 1 | Pending |
| PKG-01 | Phase 2 | Pending |
| CI-01 | Phase 2 | Pending |
| CI-02 | Phase 2 | Pending |
| IOC-01 | Phase 2 | Pending |
| TEST-01 | Phase 2 | Pending |
| CLI-01 | Phase 3 | Pending |
| CLI-02 | Phase 3 | Pending |
| CLI-03 | Phase 3 | Pending |
| CLI-04 | Phase 3 | Pending |
| CLI-05 | Phase 3 | Pending |
| TEST-02 | Phase 3 | Pending |
| ALERT-01 | Phase 4 | Pending |
| ALERT-02 | Phase 4 | Pending |
| ALERT-03 | Phase 4 | Pending |
| DOC-01 | Phase 4 | Pending |
