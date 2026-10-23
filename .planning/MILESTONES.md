# Milestones

## v1.0 MVP (Shipped: 2026-10-23)

**Phases completed:** 4 phases, 10 plans, 0 tasks

**Key accomplishments:**

- Read-only, stdlib-only scanner with safe walking (1 MB cap, skips node_modules/.git, malformed JSON = low finding, no secret values in output)
- H1/H2 hook checks, H3 package.json lifecycle scripts, H4 workflow checks, H5 lockfile IOC matching with a fixture matrix
- CLI with table and `--json` output, exit codes 0/1/2/70, default `~/Projects` scan (about 15s) and a packaged `iocs.json`
- Cron wrapper `scripts/run-alert.sh`, importable n8n workflow (Webhook, dedupe, Telegram) and a README
- 537 tests passing

Known deferred items at close: 1 (see STATE.md Deferred Items)

---
