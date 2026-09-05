# app-security-audit

A Claude Code skill that audits a whole application's security posture — the
question "if I put this URL in front of the internet tonight, what happens?" —
rather than reviewing a diff.

It covers the vulnerability classes that actually sink small and AI-assisted
apps: row-level security left off, secrets committed or shipped to the browser,
authorization enforced only in the UI, wildcard CORS, unverified webhooks, mass
assignment, unauthenticated admin routes, and the rest. Stack-agnostic.

## Install

**For every project (recommended — this is a personal skill):**

```bash
mkdir -p ~/.claude/skills
cp -r .claude/skills/app-security-audit ~/.claude/skills/
```

**For one project only:** copy it to that repo's `.claude/skills/` and commit it,
so everyone working in the repo gets it.

Restart Claude Code (or start a new session) to pick it up.

## Use

It should trigger on its own when you ask things like "is this safe to launch?"
or "check my app for security problems." To invoke it explicitly:

```
/app-security-audit
```

The scanner can also be run on its own, without Claude:

```bash
bash ~/.claude/skills/app-security-audit/scripts/scan.sh /path/to/repo
```

That prints *candidates* — grep hits that still need a human or Claude to verify.
It is deliberately over-eager; the skill's job is to check each one against the
real code before anything is called a finding.

## Layout

| Path | What it is |
|---|---|
| `SKILL.md` | The audit procedure: map the app → scan → verify → report |
| `references/checks.md` | The vulnerability classes: detection, false positives, fixes |
| `references/supabase-firebase.md` | Row-level security and database rules in depth |
| `scripts/scan.sh` | The mechanical scanner |
