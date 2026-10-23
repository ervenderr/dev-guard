# dev-guard

## What This Is

A local, read-only Python CLI that detects the persistence and credential-theft tricks used by 2026 npm/PyPI supply-chain worms (e.g. Mini Shai-Hulud) on a developer machine. Built for a solo developer on macOS. Source of truth: `SPEC.md`.

## Core Value

Catch malicious hooks/install scripts/workflow steps in dev config files even when no CVE or advisory exists yet, without ever executing or leaking the scanned content.

## Context

Malicious packages inject hooks into `.claude/settings.json` and `.vscode/tasks.json` so a payload re-runs every session after the package is removed. Install scripts steal cloud tokens and LLM API keys. Advisory-only scanners miss these early on.

## Requirements

### Validated

- ✓ H1-H5 checks, safe walking, CLI table/JSON/exit codes, default scan — v1.0
- ✓ Cron wrapper, n8n workflow (Telegram, dedupe in n8n), README — v1.0 (n8n import and real cron run not yet verified)

### Active

(None — next milestone to define)

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
| Pattern scanner first, IOC matcher second | `iocs.json` goes stale; regex catches known patterns, not novel/obfuscated ones | ✓ Good (v1.0) |
| Allowlist in `patterns.py` | Mitigates false positives on legitimate hooks | ✓ Good (v1.0) |
| Stdlib only, no YAML lib | Zero deps; H4 parses workflow YAML as text | ✓ Good (v1.0) |
| n8n alerting as separate later phase | Scanner must work standalone first | ✓ Good (v1.0) |
| Build order: H1/H2 → H3/H4/H5 → CLI → n8n | Highest-value checks first | ✓ Good (v1.0) |

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
*Last updated: 2026-10-24 after v1.0 milestone*
