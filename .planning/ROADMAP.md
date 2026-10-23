# Roadmap: dev-guard

## Overview

Build a read-only, stdlib-only Python CLI that detects supply-chain worm persistence on a macOS dev machine. Follows SPEC build order: highest-value hook checks first, then remaining checks, then the CLI surface, then n8n alerting.

## Phases

- [ ] **Phase 1: Finding Model, Safe Walking & Hook Checks** - Finding model, safe file walk, H1/H2 with tests
- [ ] **Phase 2: Package, CI & IOC Checks** - H3, H4, H5 with tests for all five checks
- [ ] **Phase 3: CLI Output & Exit Codes** - Default scan, table/JSON output, exit code, performance
- [ ] **Phase 4: n8n Alerting & README** - Cron to n8n webhook to Telegram/email, docs

## Phase Details

### Phase 1: Finding Model, Safe Walking & Hook Checks
**Goal**: Malicious Claude and VS Code hooks are detected safely from a directory tree
**Mode:** mvp
**Depends on**: Nothing (first phase)
**Requirements**: CORE-01, CORE-02, CORE-03, CORE-04, CORE-05, HOOK-01, HOOK-02, HOOK-03, HOOK-04
**Success Criteria** (what must be TRUE):
  1. Running the H1 check on a fixture `.claude/settings.json` with a `curl`/`base64 -d`/`eval` hook yields a high finding with file:line and pattern name
  2. A hook command outside the allowlist yields a finding; an allowlisted one on the clean fixture yields none
  3. A `.vscode/tasks.json` with `runOn: folderOpen` or a H1-pattern command yields a finding
  4. Malformed JSON yields a low finding instead of a crash, and files over 1 MB, `node_modules`, and `.git` are skipped
  5. No finding output contains secret values, only file:line and pattern name
**Plans:** 2 plans

Plans:
- [ ] 01-01-PLAN.md — Walking skeleton: venv/pytest, Finding model, safe walker, H1 high detection end-to-end
- [ ] 01-02-PLAN.md — H1 allowlist + malformed JSON, H2 .vscode/tasks.json check

### Phase 2: Package, CI & IOC Checks
**Goal**: Install scripts, workflow steps, and known-bad lockfile entries are detected
**Mode:** mvp
**Depends on**: Phase 1
**Requirements**: PKG-01, CI-01, CI-02, IOC-01, TEST-01
**Success Criteria** (what must be TRUE):
  1. A `package.json` with a malicious `postinstall` (H1 pattern) yields a finding
  2. A workflow referencing `ACTIONS_ID_TOKEN_*` or `/proc/*/mem` yields a finding, and a third-party action not pinned to a SHA yields a finding
  3. A lockfile or `requirements*.txt` entry listed in `iocs.json` yields a high finding
  4. Every check H1-H5 has a passing test on a clean fixture and a failing-detection test on a malicious fixture
**Plans**: TBD

### Phase 3: CLI Output & Exit Codes
**Goal**: User runs `dev-guard` and gets readable results and a usable exit code
**Mode:** mvp
**Depends on**: Phase 2
**Requirements**: CLI-01, CLI-02, CLI-03, CLI-04, CLI-05, TEST-02
**Success Criteria** (what must be TRUE):
  1. `dev-guard` with no args scans `~/Projects` plus `~`-level config files; `dev-guard <path>` scans that path
  2. Findings print as a table with severity, check ID, file:line, and pattern
  3. `dev-guard --json` prints valid machine-readable JSON findings
  4. Exit code is 1 on any high finding and 0 on a clean repo; scanning the fixtures exits 1 with the expected check IDs
  5. A scan of `~/Projects` finishes in under 30s
**Plans**: TBD

### Phase 4: n8n Alerting & README
**Goal**: User gets Telegram/email alerts on new high findings and can set it all up from the README
**Mode:** mvp
**Depends on**: Phase 3
**Requirements**: ALERT-01, ALERT-02, ALERT-03, DOC-01
**Success Criteria** (what must be TRUE):
  1. A cron entry runs `dev-guard --json` on a schedule
  2. Findings (never file contents) are POSTed to an n8n webhook
  3. A Telegram/email notification arrives only for new high findings, not repeats
  4. README documents install, usage, and the n8n webhook flow
**Plans**: TBD

## Progress

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Finding Model, Safe Walking & Hook Checks | 0/0 | Not started | - |
| 2. Package, CI & IOC Checks | 0/0 | Not started | - |
| 3. CLI Output & Exit Codes | 0/0 | Not started | - |
| 4. n8n Alerting & README | 0/0 | Not started | - |
