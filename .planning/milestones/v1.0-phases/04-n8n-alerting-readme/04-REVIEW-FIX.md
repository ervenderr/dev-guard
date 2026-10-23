---
phase: 04-n8n-alerting-readme
fixed_at: 2026-10-24T00:00:00Z
review_path: .planning/phases/04-n8n-alerting-readme/04-REVIEW.md
iteration: 1
findings_in_scope: 7
fixed: 7
skipped: 0
status: all_fixed
---

# Phase 4: Code Review Fix Report

**Source review:** 04-REVIEW.md (CR-01, WR-01..WR-05, plus IN-03 by request; other Info skipped)

**Summary:** 7 in scope, 7 fixed, 0 skipped. Each fix had a failing test first.

## Fixed Issues

### CR-01: Fingerprint marked seen before Telegram send
**Files:** `n8n/dev-guard-alert.json`, `tests/test_n8n_workflow.py`
**Applied fix:** "Filter New Highs" no longer writes static data. New "Mark Seen" Code node runs after Telegram and records the fingerprints. Message capped at 20 lines x 180 chars (under 4096); overflow stays unseen and is sent on the next run. Requires human verification (workflow logic, import into real n8n untested).

### WR-01: Dedupe permanence and fingerprint instability
**Files:** `n8n/dev-guard-alert.json`, `tests/test_n8n_workflow.py`
**Applied fix:** key is `JSON.stringify([check_id,file,line,pattern])`; seen value is a timestamp; entries absent from the current payload are pruned (only when `findings` is an array). `line` kept in the key. Requires human verification.

### WR-02: curl diagnostics discarded
**Files:** `scripts/run-alert.sh`, `tests/test_alert_wrapper.py`
**Applied fix:** logs `curl exit N, http NNN` (numeric only; stderr still discarded).

### WR-03: No URL scheme validation
**Files:** `scripts/run-alert.sh`, `tests/test_alert_wrapper.py`
**Applied fix:** URL must be `https://` (or `http://127.0.0.1` for the stub tests); rejects `"`, backslash, `@` (userinfo spoofing of the loopback exception), and any control char. `--proto` not added. Same commit as WR-02 (both are the same block of the script). Requires human verification.

### WR-04: --exclude case/typo handling
**Files:** `dev_guard/checks.py`, `dev_guard/cli.py`, `tests/test_cli.py`
**Applied fix:** `iter_files` compares by (st_dev, st_ino), so spelling/case no longer matters; the CLI warns on stderr for a nonexistent exclude. Requires human verification (security-relevant matching).

### WR-05: tests/ blind spot and failure signal
**Files:** `README.md`, `tests/test_readme.py`
**Applied fix:** README states the tests/ blind spot and tells the user to tail `~/.dev-guard-cron.log`. No new alerting.

### IN-03: README exit codes
**Files:** `README.md`, `tests/test_readme.py`
**Applied fix:** 64/75 rows in the exit-code table; clarified the "no network calls" claim; 0600 note for the crontab. Same commit as WR-05. The old "indefinitely" dedupe note was replaced to match WR-01.

---

_Fixer: Claude (gsd-code-fixer)_
