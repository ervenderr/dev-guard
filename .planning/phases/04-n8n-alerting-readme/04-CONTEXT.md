# Phase 4: n8n Alerting & README - Context

**Gathered:** 2026-10-24
**Status:** Ready for planning

<domain>
## Phase Boundary

User gets a Telegram alert on new high findings and can set it all up from the README (ALERT-01..03, DOC-01). Delivers: a repeatable `--exclude` CLI flag, a cron wrapper script, an importable n8n workflow JSON, and the README. Scanner itself stays stateless, read-only, no network.

</domain>

<decisions>
## Implementation Decisions

### Fixture noise
- **D-01:** Add a repeatable `--exclude PATH` flag to the CLI (extends the Phase 3 flag surface). Excluded subtrees are skipped by the walk; the cron wrapper passes the dev-guard `tests/` dir. Needs a failing test first; exit codes and JSON shape unchanged.

### Dedupe
- **D-02:** Dedupe lives in n8n (workflow static data keeps seen fingerprints), not in the scanner or wrapper. Fingerprint = check_id + file + line + pattern. Alert only on high severity findings not seen before.

### Deliverables
- **D-03:** `scripts/run-alert.sh`: runs `dev-guard --json --exclude <tests dir>`, POSTs the JSON (findings only, never file contents) with curl to the URL in env var `DEV_GUARD_WEBHOOK_URL`; exits non-zero with a stderr message if the variable is unset; never echoes the URL. Treats dev-guard exit 0/1 as success and 2/70 as failure.
- **D-04:** `n8n/dev-guard-alert.json`: importable workflow: Webhook (POST) -> Code (filter high, dedupe via static data) -> IF any new -> Telegram. Telegram credential is referenced by n8n credential name only; no tokens/chat ids in the file.
- **D-05:** README documents install (`pip install -e .`), usage, flags, exit codes 0/1/2/70, the `DEV_GUARD_IOCS` override, the n8n webhook flow (import JSON, set credential, copy webhook URL into env var), and a sample crontab line for the user to install themselves.
- **D-06:** Nothing outward-facing is done by the build: no crontab edit, no real webhook POST, no real URL. Verification uses a local stub HTTP receiver in tests.

### Channel
- **D-07:** Telegram only (no email node).

### Claude's Discretion
Wrapper details (mktemp, curl flags/timeouts), Code-node JS, README structure.

</decisions>

<canonical_refs>
## Canonical References

- `SPEC.md` — Alerting section: findings only to n8n, never file contents
- `.planning/REQUIREMENTS.md` — ALERT-01..03, DOC-01
- `.planning/phases/03-cli-output-exit-codes/03-02-SUMMARY.md` — always-exit-1 default scan handoff
- `.planning/phases/03-cli-output-exit-codes/03-REVIEW-FIX.md` — exit code behaviour (2 bad root, 70 internal)
- `dev_guard/cli.py` — argparse surface for `--exclude`

</canonical_refs>

<code_context>
## Existing Code Insights

- `cli.py` exposes `build_parser`, `run_scan`, `sanitize`; scan per root with dedupe by realpath; `print` banned in `dev_guard/*.py` (use sys.stdout.write).
- JSON output: `{"findings":[{check_id,severity,file,line,pattern}],"summary":{high,med,low}}` — contains no matched text.
- `iocs.json` now lives in `dev_guard/`.

</code_context>

<specifics>
## Specific Ideas

Webhook URL and Telegram credentials are secrets: env var / n8n credential only, never in repo.

</specifics>

<deferred>
## Deferred Ideas

- Email notification node
- launchd plist instead of cron
- Dedupe state in the scanner

</deferred>
