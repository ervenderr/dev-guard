<!-- GSD:project-start source:PROJECT.md -->
## Project

**dev-guard**

A local, read-only Python CLI that detects the persistence and credential-theft tricks used by 2026 npm/PyPI supply-chain worms (e.g. Mini Shai-Hulud) on a developer machine. Built for a solo developer on macOS. Source of truth: `SPEC.md`.

**Core Value:** Catch malicious hooks/install scripts/workflow steps in dev config files even when no CVE or advisory exists yet, without ever executing or leaking the scanned content.

### Constraints

- **Stack**: Python 3.12, stdlib only (`json`, `re`, `pathlib`, `argparse`); pytest for tests; no dependencies
- **Security**: never print secret values (file:line + matched pattern only); parse text only
- **Performance**: scan of `~/Projects` under 30s
- **Layout**: `dev_guard/{cli,checks,patterns}.py`, `iocs.json`, `tests/` with clean + one malicious fixture per check
<!-- GSD:project-end -->

<!-- GSD:stack-start source:STACK.md -->
## Technology Stack

Technology stack not yet documented. Will populate after codebase mapping or first phase.
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

Conventions not yet established. Will populate as patterns emerge during development.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

Architecture not yet mapped. Follow existing patterns found in the codebase.
<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->
## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, `.github/skills/`, or `.codex/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->



<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
