---
phase: 04-n8n-alerting-readme
verified: 2026-10-24T00:00:00Z
status: human_needed
score: 4/4 must-haves verified
gaps: []
human_verification:
  - test: "Import n8n/dev-guard-alert.json into a real n8n, set Telegram credential and chat id, activate, POST a sample payload twice"
    expected: "Nodes load without errors; first POST sends a Telegram message; identical second POST sends none"
    why_human: "Needs a real n8n instance and Telegram bot (outward-facing, D-06); typeVersions were written from memory"
  - test: "Install the sample crontab line yourself and let it fire once"
    expected: "run-alert.sh runs with cron's PATH/env and macOS file access"
    why_human: "Build must not edit crontab (D-06)"
---

# Phase 4: n8n Alerting & README Verification Report

**Goal:** User gets Telegram alerts on new high findings and can set it all up from the README.
**Status:** human_needed (all automated checks pass; real n8n/Telegram/cron not exercised)

## Roadmap Success Criteria

| # | Criterion | Status | Evidence |
|---|-----------|--------|----------|
| 1 | Cron entry runs `dev-guard --json` on a schedule | VERIFIED (sample only, by design) | README sample crontab line calls `scripts/run-alert.sh`, which runs `python -m dev_guard --json --exclude <repo>/tests`; not installed (D-06) |
| 2 | Findings (never contents) POSTed to webhook | VERIFIED | Ran wrapper against local 127.0.0.1 stub: received body was only `{"findings":[{check_id,severity,file,line,pattern}],"summary":{...}}`; planted string `SECRETVALUE123` absent |
| 3 | Notification only for new high findings | VERIFIED statically | Code node filters `severity==='high'`, fingerprint `check_id|file|line|pattern` in `$getWorkflowStaticData('global')`, IF count>0 gates Telegram; pytest dedupe tests pass. Not run in real n8n |
| 4 | README documents install, usage, n8n flow | VERIFIED | README has Install, Usage, Exit codes, IOC override, n8n steps, Cron sample, limits |

## Decisions

| D | Status | Evidence |
|---|--------|----------|
| D-01 --exclude | VERIFIED | Repeatable; excluded dir `skipme` produced no findings, exit/JSON shape unchanged |
| D-02 dedupe in n8n | VERIFIED | Static-data fingerprint in Code node |
| D-03 wrapper | VERIFIED | Unset var -> stderr message, exit 64, no scan/POST. Scanner rc 0/1 -> success; bad root rc 2 -> wrapper exits 2 with no POST. Dead receiver -> exit 75, URL not echoed (URL passed via curl config on stdin, curl stderr discarded). Clean tree posts empty findings, exit 0 |
| D-04 workflow JSON | VERIFIED | Webhook -> Code -> IF -> Telegram; credential by name only |
| D-05 README | VERIFIED | Present; flags match `--help` |
| D-06 nothing outward | VERIFIED | Only 127.0.0.1 stub used; no crontab edit |
| D-07 Telegram only | VERIFIED | No email node |

## Checks run

- `.venv/bin/python -m pytest -q`: 523 passed.
- `python -m dev_guard --json --exclude <skipme> <tree>`: 3 high H1 findings (base64_decode, eval, network_fetch), rc 1; skipme excluded.
- Secret grep over README, scripts/run-alert.sh, n8n JSON for URLs, bot-token shape, chat ids: only placeholder `REPLACE_WITH_CHAT_ID`. No URLs.
- git working tree: only `.claude/` and `SPEC.md` untracked (not committed).

## Findings

| Severity | Item |
|----------|------|
| WARNING (doc) | README says `--exclude PATH` "skip a path", but excluding a single file does nothing (verified: file path exclude still reported its findings). `--help` correctly says "directory subtree". Fix wording or support files |
| INFO | `typeVersion` values and the `responseMode: onReceived` / IF v2 condition shape were not validated against a real n8n; README already tells the user to confirm on import |
| INFO | Static data never expires seen fingerprints (documented); a finding that disappears and returns will not re-alert |
| INFO | Wrapper with no args scans real `~/Projects` and `~/.claude` (not run here) |

## Not verified

- Real n8n import/execution and Telegram delivery
- Cron execution environment (PATH, python 3.12, macOS Full Disk Access)

_Verifier: Claude (gsd-verifier)_
