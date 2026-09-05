---
name: app-security-audit
description: Audit an application's real security posture against the vulnerability classes that actually get small and AI-assisted ("vibe coded") apps breached — database row-level security left off, secrets committed or shipped to the browser, authorization enforced only in the UI, wildcard CORS, unverified webhooks, mass assignment, unauthenticated admin routes, and the rest. Use this whenever the user asks if their app is secure, safe to launch, safe to make public, or ready for real users; whenever they ask for a security check, audit, or review of a project, repo, or app as a whole; before a first deploy or public launch; when they worry about leaked API keys, an exposed database, or Supabase/Firebase permissions; or when they paste a security checklist and ask whether it applies to them. Prefer this over diff-based code review whenever the question is about the whole app's posture rather than about the changes in one commit or PR.
---

# App security audit

## What this is for

Diff-based review asks "is this change safe?" This asks a different question: **"if I put this URL in front of the internet tonight, what happens?"**

That question is worth its own procedure because the vulnerabilities that actually sink small apps are almost never in the diff. They are *absences* — a policy never written, a check never added, a default never changed. Nothing shows up in a code review because nothing was written. No linter fails. No test goes red. The app works perfectly, and it works perfectly for attackers too.

## The one idea underneath most of it

Nearly every finding you will make is a variation of a single mistake: **the client was trusted.**

The browser, the mobile app, the `curl` on someone's laptop — all of it is under the attacker's control. They can read every byte you shipped, call every endpoint you expose in any order with any payload, and skip your UI entirely. So:

- Hiding the admin button doesn't remove the admin endpoint.
- A key in the bundle is a published key.
- Client-side validation is a UX feature, not a security control.
- A sequential ID lets someone count.
- `role` in a request body is a *claim*, never a fact.

Hold that idea while you audit. It generalizes past any checklist and tells you what to look for in stacks and frameworks this skill has never heard of. When you find something not on the list, that's the skill working, not failing.

## Method

Work in four phases. The order matters — phase 3 is what separates a useful audit from a scary-looking list of grep hits.

### Phase 1 — Map the app

You cannot audit what you cannot describe. Before searching for anything, establish:

- **What runs where.** Which code ships to the browser, which runs on a server you control, which runs in a serverless function.
- **Where the data lives** and who talks to it. A browser holding a database client directly (Supabase, Firebase, PocketBase) is a completely different threat model from a browser talking to your API — in the first, the *database* is your security boundary, so every finding about database rules is critical rather than theoretical.
- **How a request is authenticated,** and where that check physically happens.
- **What's actually deployed.** A local-only experiment with no users has a different risk profile from something with a public URL and a payments integration. Ask if you can't tell — it changes what counts as critical.

Read `package.json` / `requirements.txt` / `go.mod`, the route or page directory, and any config for the hosting platform. Two or three minutes here makes everything after it accurate.

Write down the trust boundary in one sentence. If you can't, you don't understand the app well enough to audit it yet.

### Phase 2 — Mechanical scan

Run the bundled scanner to sweep the cheap, deterministic patterns:

```bash
bash .claude/skills/app-security-audit/scripts/scan.sh          # or wherever the skill is installed
bash <skill-path>/scripts/scan.sh /path/to/repo                 # explicit target
```

It reports committed `.env` files, secrets in git history, secret-shaped strings in client bundles, wildcard CORS, tokens in `localStorage`, SQL string concatenation, raw HTML sinks, unsigned webhook handlers, and missing RLS in migrations.

**Its output is a list of candidates, not a list of findings.** Treat it as a search, not a verdict. It is deliberately over-eager: false positives you discard cost you a minute, missed classes cost the user their database.

Then read `references/checks.md` for the classes the scanner cannot see — those need reasoning about the code, not pattern matching. For anything backed by Supabase or Firebase, also read `references/supabase-firebase.md`; row-level security is the single most common catastrophic finding and it has a specific verification procedure.

### Phase 3 — Verify before you report

This is the phase that makes the audit trustworthy, and it is the one under time pressure you'll be tempted to skip. Don't.

For every candidate, open the file and answer three questions concretely:

1. **Can an unauthenticated stranger reach this?** Trace the actual path. A `dangerouslySetInnerHTML` fed by a hardcoded constant is not a vulnerability. One fed by a username is.
2. **What exactly do they get?** Name the data or the action. "Could be exploited" is not a finding; "can read every row of `profiles`, including email addresses" is.
3. **Can I write the exploit?** If you can't sketch the request that does the damage, you have not yet verified it. Sketch it in the report.

Discard anything that survives none of these. **A security report that cries wolf gets ignored entirely**, which is strictly worse than no report — it burns the user's attention on noise and teaches them to skim the next one, including the one that mattered.

Two false positives worth knowing by name, because flagging them is the classic tell of an unverified audit:

- **A publishable/anon key in front-end code is correct by design.** Supabase anon keys, Firebase config, Stripe publishable keys, PostHog keys — these are *meant* to ship to the browser. The vulnerability is never their presence; it is the absence of the server-side rules that make them safe to publish. Check the rules and report *that*. Flagging the key itself tells the user you didn't understand their stack.
- **A `service_role` key, `sk_live_`, or any admin key in front-end code is the opposite** — always critical, no verification needed beyond confirming the file ships to the client.

### Phase 4 — Report

Order strictly by blast radius, not by category and not by how easy it was to find. The user will read the first item and maybe the second. Whatever can drain the database goes first.

Use this structure:

```markdown
# Security audit: <app>

**Stack:** <one line>
**Trust boundary:** <one line — where does trusted code end?>
**Verdict:** <one line — e.g. "2 critical issues; do not launch until #1 and #2 are fixed">

## Critical — fix before real users touch this

### 1. <specific title> — `path/to/file.ts:42`
**What's wrong:** <one or two sentences>
**How it's exploited:** <the concrete request, curl, or console snippet>
**Fix:** <the specific change, with code where it's short>

## Serious — fix soon

## Worth doing

## Checked and clean
- <check>: <what you found that was right, with the file that proves it>

## Not checked
- <check>: <why — e.g. "rate limiting is configured at the CDN, not visible in this repo">
```

The last two sections are not filler — they are what make the report honest. Without them the user cannot distinguish "this is fine" from "nobody looked," and those two look identical on the page. **Never let a check you skipped read as a check that passed.** If the repo doesn't contain the answer (infra config, dashboard settings, environment variables set in a hosting provider), say so and tell the user exactly where to look.

## Fixing

Report first, fix on request. Security changes touch auth and access paths, which is precisely the code where a confident wrong edit locks out real users or silently widens the hole. The user should see the finding before the patch.

Two exceptions worth acting on immediately, because delay makes them worse:

- **A committed secret needs rotation, not deletion.** Deleting the file leaves it in git history, and public-repo secrets are scraped within minutes of the push. Say this the moment you find one: rotate the key first, then clean the file. Removing it from history is optional cleanup; rotation is the fix.
- **If the user says they're mid-launch or already live**, lead with the shortest path to safe — often a feature flag, a temporary deny-all policy, or taking one route offline — before the proper fix.

When asked to fix, do the smallest change that closes the hole and say what you couldn't verify. Then re-run the relevant check to confirm it actually closed.

## Reference files

- `references/checks.md` — the vulnerability classes: what each one is, how to detect it, what its false positives look like, and how to fix it. Read this in phase 2.
- `references/supabase-firebase.md` — row-level security and database rules in depth. Read whenever the app uses Supabase, Firebase, or any browser-to-database setup.
- `scripts/scan.sh` — the mechanical scanner.
