---
phase: 04-n8n-alerting-readme
plan: 02
subsystem: alerting
tags: [cron, n8n, telegram, webhook]
requires: [04-01]
provides: [scripts/run-alert.sh, n8n/dev-guard-alert.json]
key-files:
  created: [scripts/run-alert.sh, n8n/dev-guard-alert.json, tests/test_alert_wrapper.py, tests/test_n8n_workflow.py]
requirements-completed: [ALERT-01, ALERT-02, ALERT-03]
metrics:
  completed: 2026-10-24
---

# Phase 4 Plan 2: n8n alerting Summary

Cron wrapper POSTs the dev-guard JSON (findings + summary only) to the webhook in DEV_GUARD_WEBHOOK_URL, and an importable n8n workflow dedupes new highs and sends them to Telegram.

## Commits
- 4c5a14f test: add failing alert wrapper tests (RED)
- 175d1ee feat: add cron alert wrapper script (GREEN)
- 3442e4d test: add failing n8n workflow tests (RED)
- cd1d480 feat: add n8n alert workflow (GREEN)

## Behaviour
- run-alert.sh: unset/empty var or URL with quote/newline -> exit 64; dev-guard rc other than 0/1 -> that rc, no POST; URL passed to curl via `-K -` stdin, curl stderr discarded, failure -> exit 75. Always excludes `<repo>/tests`. No URL literals, no crontab use.
- Workflow: Webhook(POST, path dev-guard) -> Filter New Highs (Code) -> Any New? (count > 0) -> Telegram. Fingerprint check_id|file|line|pattern in workflow static data. Credential "Telegram account" by name, chatId placeholder REPLACE_WITH_CHAT_ID.

## Verification
- Wrapper tests: 7 passed against a 127.0.0.1 stub (happy, clean, unset, exit 2, HTTP 500, unreachable, DGSECRET marker absent from body, URL token absent from output).
- Workflow tests: 6 passed. The node-based dedupe test RAN (node found at /opt/homebrew/bin/node), not skipped: run 1 = 2 new highs, run 2 = 0, run 3 = 1 (only the new one), empty payload = 0.
- Full suite: 516 passed.
- Grep gates: no `https?://` in script or workflow; REPLACE_WITH_CHAT_ID appears once.

## Deviations from Plan
- Task 2 verify gate uses `[[:space:]]` instead of `\s` (macOS BSD grep), as instructed.
- A temporary generator script was used to write the workflow JSON and deleted before commit.

## Notes
- n8n static data persists only for active (production) webhook executions, not manual test runs; README plan 03 should say so.
- Webhook is unauthenticated; the secret path is the control (T-04-07 accepted).

## Self-Check: PASSED
