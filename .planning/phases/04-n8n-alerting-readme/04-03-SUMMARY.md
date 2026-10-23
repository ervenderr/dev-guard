---
phase: 04-n8n-alerting-readme
plan: 03
subsystem: docs
tags: [readme, n8n, cron]
requires: [04-01, 04-02]
provides: [README.md, tests/test_readme.py]
key-files:
  created: [README.md, tests/test_readme.py]
  modified: [.planning/REQUIREMENTS.md]
requirements-completed: [DOC-01, ALERT-01]
metrics:
  completed: 2026-10-24
---

# Phase 4 Plan 3: README Summary

README covers install, usage, every CLI flag, exit codes 0/1/2/70, DEV_GUARD_IOCS, the n8n import/Telegram/activate/webhook flow and a placeholder-only sample crontab; tests keep it in sync with the CLI parser and repo paths.

## Commits
- 38063b3 test: add failing readme consistency tests (RED)
- 89f5e17 docs: add README with n8n alerting setup (GREEN)
- 35b298a docs: mark phase 4 requirements complete

## Deviations
- Plan-checker fixes applied: cron regex `^\s*(\S+\s+){5}\S*run-alert\.sh`, `[[:space:]]` for BSD grep, README note on indefinite fingerprint retention and production-webhook-only static data, and a note to import the workflow once and confirm nodes load (typeVersion written from memory).
- Commit 38063b3 mistakenly carries Co-Authored-By/Claude-Session trailers (contrary to the no-attribution rule). Not amended, per the no-amend rule; later commits have none.

## Verification
- tests/test_readme.py: 7 passed. No `/Users/` or webhook URL in README. Crontab never touched.
