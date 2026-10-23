# dev-guard

## What This Is

A local, read-only Python CLI that detects the persistence and credential-theft tricks used by 2026 npm/PyPI supply-chain worms (e.g. Mini Shai-Hulud) on a developer machine. Built for a solo developer on macOS. Source of truth: `SPEC.md`.

## Core Value

Catch malicious hooks/install scripts/workflow steps in dev config files even when no CVE or advisory exists yet, without ever executing or leaking the scanned content.

## Context

Malicious packages inject hooks into `.claude/settings.json` and `.vscode/tasks.json` so a payload re-runs every session after the package is removed. Install scripts steal cloud tokens and LLM API keys. Advisory-only scanners miss these early on.

## Requirements

### Validated

(None yet — ship to validate)

### Active

- [ ] H1: flag `.claude/settings.json` (project + `~/.claude`) hooks running network fetch (`curl`/`wget`/`nc`), `base64 -d`, `eval`, remote `sh -c`, or any command not in the allowlist
- [ ] H2: flag `.vscode/tasks.json` tasks with `runOn: folderOpen` or commands matching H1 patterns
- [ ] H3: flag `package.json` `preinstall`/`install`/`postinstall` scripts matching H1 patterns
- [ ] H4: flag `.github/workflows/*.yml` steps touching `ACTIONS_ID_TOKEN_*`, `/proc/*/mem`, or unpinned (no SHA) third-party actions
- [ ] H5: flag lockfile (`package-lock.json`, `pnpm-lock.yaml`, `requirements*.txt`) package@version present in local `iocs.json`
- [ ] Terminal table output (severity, check ID, file:line, matched pattern); `--json`; exit 1 on any high finding
- [ ] Default scan of `~/Projects` plus `~`-level config files
- [ ] Safe walking: 1 MB file cap, skip `node_modules`/`.git`, malformed JSON = low finding, never print secret values, never execute scanned content
- [ ] README: install, usage, n8n webhook flow
- [ ] Phase 2 alerting: cron runs `dev-guard --json` → n8n webhook → Telegram/email on new high findings (findings only, never file contents)

### Out of Scope

- Auto-remediation / deletion — read-only by design
- Malware sandboxing
- Windows/Linux paths — macOS first
- Web dashboard
- Live advisory feeds — v1 uses static hand-updated `iocs.json`
- Network access in the scanner itself

## Constraints

- **Stack**: Python 3.12, stdlib only (`json`, `re`, `pathlib`, `argparse`); pytest for tests; no dependencies
- **Security**: never print secret values (file:line + matched pattern only); parse text only
- **Performance**: scan of `~/Projects` under 30s
- **Layout**: `dev_guard/{cli,checks,patterns}.py`, `iocs.json`, `tests/` with clean + one malicious fixture per check

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Pattern scanner first, IOC matcher second | `iocs.json` goes stale; regex catches known patterns, not novel/obfuscated ones | — Pending |
| Allowlist in `patterns.py` | Mitigates false positives on legitimate hooks | — Pending |
| Stdlib only, no YAML lib | Zero deps; H4 parses workflow YAML as text | — Pending |
| n8n alerting as separate later phase | Scanner must work standalone first | — Pending |
| Build order: H1/H2 → H3/H4/H5 → CLI → n8n | Highest-value checks first | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd:complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-10-23 after initialization*
