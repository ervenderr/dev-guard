# dev-guard

A local, read-only CLI that spots the persistence and credential-theft tricks used by npm/PyPI supply-chain worms (for example Mini Shai-Hulud) in your dev config files, even when no CVE or advisory exists yet. It only parses text: it never executes scanned content, makes no network calls itself (only the optional alert wrapper below does), and never prints secret values (only check id, `file:line` and the matched pattern).

| Check | Looks for |
|-------|-----------|
| H1 | Suspicious hooks in `.claude/settings*.json` |
| H2 | Suspicious VS Code / editor task auto-run config |
| H3 | Malicious npm install scripts in `package.json` |
| H4 | Suspicious GitHub Actions workflow steps |
| H5 | Known IOC strings from the IOC list |

## Install

```sh
python3.12 -m venv .venv && . .venv/bin/activate && pip install -e .
```

## Usage

```sh
dev-guard                       # scans ~/Projects plus ~/.claude/settings.json and settings.local.json
dev-guard PATH...               # scan only these paths
dev-guard --json                # machine-readable findings
dev-guard --exclude PATH        # skip a directory subtree (files are not matched); repeatable (e.g. dev-guard's own tests/ fixtures)
dev-guard --version
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | clean, no high findings |
| 1 | at least one high finding |
| 2 | bad path or usage error |
| 70 | internal error |
| 64 | `scripts/run-alert.sh` only: webhook URL missing or invalid |
| 75 | `scripts/run-alert.sh` only: webhook POST failed |

## IOC list

The default list is `dev_guard/iocs.json`, updated by hand. Point `DEV_GUARD_IOCS=/path/to/iocs.json` at another file to override it.

## Alerting with n8n

Flow: cron -> `scripts/run-alert.sh` -> n8n webhook -> Telegram.

1. In n8n, use Import from File with `n8n/dev-guard-alert.json`. Import it once and confirm the Webhook, IF and Telegram nodes load without errors (the node typeVersion values were written from memory and may need a bump for your n8n version).
2. Create a Telegram credential named "Telegram account" (bot token from BotFather, entered only in n8n) and replace `REPLACE_WITH_CHAT_ID` in the Telegram node.
3. Activate the workflow and copy the Production webhook URL. Seen-finding dedupe lives in workflow static data, which persists only on the activated production webhook, not the Test URL. A seen fingerprint is dropped once its finding stops being reported, so a finding that is fixed and later returns alerts again.
4. `export DEV_GUARD_WEBHOOK_URL=<production webhook url>` (never commit it).

Only findings (check id, `file:line`, pattern) are sent, never file contents. Telegram fires only for high findings not seen before.

## Cron

`scripts/run-alert.sh [scan paths]` needs `DEV_GUARD_WEBHOOK_URL`; set `DEV_GUARD_PYTHON` to a python 3.12+ if the default is older. The URL must be `https://` (plain `http://` only for `127.0.0.1`). The wrapper always excludes the repo's `tests/` directory, so anything placed there is never scanned. It exits 64 on a missing or bad URL, 75 if the POST fails (the log line has the curl exit code and HTTP status, never the URL), and passes through 2/70 from the scanner.

Nothing alerts you when the wrapper itself fails or n8n is down, so check the log now and then: `tail ~/.dev-guard-cron.log`. The webhook URL is the only secret, so keep the crontab (or any env file you source) private (`chmod 600`).

Sample for you to install yourself with `crontab -e` (placeholders only; this project never edits your crontab):

```
DEV_GUARD_WEBHOOK_URL=<your production webhook url>
DEV_GUARD_PYTHON=/path/to/python3.12
0 9 * * * /path/to/dev-guard/scripts/run-alert.sh >> $HOME/.dev-guard-cron.log 2>&1
```

On macOS, cron may need Full Disk Access to read `~/Projects`.

## Limits

It is a pattern scanner and can be evaded by obfuscation, and the IOC list goes stale unless you update it.
