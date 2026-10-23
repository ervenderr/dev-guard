---
phase: 04-n8n-alerting-readme
reviewed: 2026-10-24T00:00:00Z
depth: standard
files_reviewed: 9
files_reviewed_list:
  - dev_guard/cli.py
  - dev_guard/checks.py
  - scripts/run-alert.sh
  - n8n/dev-guard-alert.json
  - README.md
  - tests/test_cli.py
  - tests/test_alert_wrapper.py
  - tests/test_n8n_workflow.py
  - tests/test_readme.py
findings:
  critical: 1
  warning: 5
  info: 3
  total: 9
status: issues_found
---

# Phase 4: Code Review Report

**Reviewed:** 2026-10-24
**Depth:** standard
**Files Reviewed:** 9
**Status:** issues_found

## Summary

The wrapper is sound on its main concerns. The URL stays out of argv via `-K -`, and quotes and newlines are rejected. The temp file comes from `mktemp` (mode 0600) and is removed by a trap. Exit codes 0/1 are treated as scan success and anything else aborts before the POST. The payload is findings and summary only. The weak spot is the n8n dedupe: it marks findings as seen before delivery is confirmed, so alerts can be lost silently. The other problems are lost curl diagnostics, no URL scheme check, and exclude edge cases.

## Critical Issues

### CR-01: Fingerprint is marked "seen" before Telegram delivery, so failed sends lose the alert permanently

**File:** `n8n/dev-guard-alert.json` (Filter New Highs jsCode, `store.seen[fp] = true`)
**Issue:** The Code node writes to static data before the Telegram node runs. If Telegram fails, the high finding is already in `seen`, and no later run re-alerts it. Failures include an expired bot token, a wrong chat id (the shipped placeholder `REPLACE_WITH_CHAT_ID` is one), a Telegram outage, or a message over 4096 characters when many findings arrive at once. A malicious hook is then never reported, which defeats the tool's purpose. The wrapper cannot see this, because the webhook uses `onReceived` and replies 200 immediately. Execution-level failures never reach cron, so the user sees nothing.
**Fix:** Split the node in two. Compute `fresh` without writing to static data, and send it. Commit the fingerprints only after the Telegram node succeeds, using a second Code node after Telegram that writes `seen`. Also chunk the message to 4000 characters or fewer, or cap it at N lines plus "and M more". As a minimum, set an Error Workflow or `continueOnFail` plus an alert path.

## Warnings

### WR-01: Permanent suppression and fingerprint instability in the dedupe

**File:** `n8n/dev-guard-alert.json` (jsCode, `fp = [check_id, file, line, pattern].join('|')`)
**Issue:**
- `seen` is never pruned and never expires. A finding that is fixed and later re-introduced at the same location (a re-infection, which is the worm scenario) is never alerted again.
- Including `line` means that any edit shifting lines re-alerts the same finding (noise), while an unrelated file at the same line collides only by chance.
- `|` is not escaped. A path or pattern containing `|` can produce ambiguous or colliding fingerprints.
- The store grows without bound. The README documents this, but it is still a design flaw.
**Fix:** Store `seen[fp] = lastSeenTimestamp`. On each run, delete entries for fingerprints that were absent from the current full payload, so that a finding which disappears and returns re-alerts. Alternatively expire entries after N days. Build the key with `JSON.stringify([check_id, file, line, pattern])`.

### WR-02: All curl diagnostics are discarded, so cron failures cannot be diagnosed

**File:** `scripts/run-alert.sh:30-35`
**Issue:** `>/dev/null 2>&1` hides everything, including the HTTP status and curl's exit code. The wrapper logs only "webhook POST failed" and exits 75 for DNS failures, TLS errors, timeouts, 404 (inactive workflow or Test URL used) and 500 alike. The most common setup mistake, using the Test URL or an inactive workflow, therefore looks identical to an outage. Capturing stderr would be safe only if the URL were scrubbed.
**Fix:** Capture curl's exit code and print only that (`rc=$?; echo "run-alert: webhook POST failed (curl exit $rc)"`). Use `-w '%{http_code}'` on stdout and print only the numeric code. Neither leaks the URL.

### WR-03: No URL scheme validation, so a plain http:// secret path can be sent in cleartext

**File:** `scripts/run-alert.sh:7-14`
**Issue:** Only quote and newline are rejected. A value like `http://...`, a typo, or `file://` or `ftp://` is passed to curl as is. The webhook path is the only authentication (T-04-07), so sending it over http leaks the secret. A value with `\r` or a backslash is also not rejected. Inside the curl config's quoted string, backslash escapes such as `\n` and `\t` are interpreted, which silently mangles the URL.
**Fix:**
```bash
case "$url" in https://*) ;; *) echo "run-alert: webhook URL must be https" >&2; exit 64;; esac
case "$url" in *[$'\r\\']*) echo "run-alert: invalid character" >&2; exit 64;; esac
```
Add `--proto '=https'` to the curl call as defense in depth. Allow http only for 127.0.0.1 if the tests need it (the stub tests currently use http://127.0.0.1).

### WR-04: --exclude matching is case-sensitive on a case-insensitive filesystem and silent on typos

**File:** `dev_guard/cli.py:121`, `dev_guard/checks.py:89,97`
**Issue:** The default macOS APFS volume is case-insensitive. `os.path.realpath` does not normalize case, so `--exclude ~/projects/dev-guard/tests` will not match the walked `~/Projects/dev-guard/tests`. Nothing is excluded and the clean-machine exit-0 guarantee silently breaks, producing false alerts. Nonexistent exclude paths are also ignored without a warning, so a typo has the same effect. The wrapper's own `$root/tests` path is derived from `pwd` and is consistent, so it is unaffected. Only manual use is exposed.
**Fix:** Compare with `os.path.samefile` or `st_dev` and `st_ino` for each walked directory. Alternatively apply `os.path.normcase` and a case-fold on darwin. Print a stderr warning for an exclude path that does not exist.

### WR-05: Wrapper permanently blinds the scan to the repo's tests/ tree, and a failed run leaves no durable signal

**File:** `scripts/run-alert.sh:22`
**Issue:** `--exclude "$root/tests"` is unconditional. If a user copies dev-guard fixtures elsewhere they are scanned, but nothing in `tests/` is ever scanned, including anything an attacker plants there once the repo is cloned under `~/Projects`. This is an accepted tradeoff and should be documented as such (the README says only that it excludes `tests/`). A failing run (exit 75/64/70) only writes one line to a log nobody reads. If n8n is down, the user gets no alert that monitoring has stopped.
**Fix:** State the blind spot in the README Limits section. Consider an optional second heartbeat or failure notification (for example Healthchecks-style, via a second env var), or at least document tailing `~/.dev-guard-cron.log`.

## Info

### IN-01: Telegram message will carry n8n attribution and may exceed the length limit

**File:** `n8n/dev-guard-alert.json` (Telegram node, `additionalFields: {}`)
**Issue:** The n8n Telegram node appends "sent automatically with n8n" by default. Add `appendAttribution: false`. The message length is unbounded (see CR-01).

### IN-02: Workflow typeVersions are acknowledged as written from memory, and the node dedupe test can skip

**File:** `n8n/dev-guard-alert.json`, `tests/test_n8n_workflow.py:89`
**Issue:** The README tells users to confirm the nodes load, which is honest but means the import is not verified. The dedupe test is skipped when node is absent, so CI without node does not exercise the only real logic. The wrapper tests also skip module-wide without bash or curl. This does not fail loudly.
**Fix:** Verify the import once against a real n8n and pin the n8n version in the README. Consider failing instead of skipping in CI.

### IN-03: README accuracy gaps

**File:** `README.md`
**Issue:**
- The exit-codes table omits the wrapper's 64 and 75. They are listed only in the Cron section, so the two are split across the document.
- The opening claims "makes no network calls itself", which is true of the CLI but not of the wrapper, and the section transition is easy to misread.
- The sample crontab is correct, but a literal `%` in a crontab command line would need escaping. This is not relevant to the env lines, though a webhook URL placeholder may mislead users into thinking quoting is needed.
- The crontab shows plain `DEV_GUARD_WEBHOOK_URL=` in the file, which stores the secret URL in the crontab and in shell history if typed. Consider noting that the file should be 0600, or sourcing a chmod-600 env file from the cron line.

---

_Reviewed: 2026-10-24_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
