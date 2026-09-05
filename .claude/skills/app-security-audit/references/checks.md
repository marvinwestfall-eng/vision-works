# Vulnerability classes

Grouped by the underlying mistake rather than by checklist number, because that's how you recognize them in a stack you've never seen. The bracketed numbers map to the widely-circulated "20 ways to get your vibe coded app hacked" list so findings are easy to cross-reference.

Each entry gives: **what it is → how to detect → what a false positive looks like → the fix.**

## Contents

- [A. Secrets that shouldn't be readable](#a-secrets-that-shouldnt-be-readable) — [1] committed `.env`, [2] keys in the front end
- [B. Authorization that isn't enforced server-side](#b-authorization-that-isnt-enforced-server-side) — [3] no RLS, [4] front-end permissions, [11] open admin panel, [14] predictable IDs
- [C. Input treated as trustworthy](#c-input-treated-as-trustworthy) — [6] SQL concatenation, [7] no validation, [8] raw HTML, [15] mass assignment, [20] file uploads
- [D. Identity and sessions](#d-identity-and-sessions) — [9] plaintext passwords, [10] tokens in localStorage, [13] no email verification, [19] no password strength
- [E. Boundary and operational config](#e-boundary-and-operational-config) — [5] no rate limiting, [12] wildcard CORS, [16] unverified webhooks, [17] prod stack traces, [18] stale dependencies

---

## A. Secrets that shouldn't be readable

### [1] `.env` committed to the repository

**What:** Credentials in git. On a public repo they are scraped by automated bots within minutes of the push — this is not a hypothetical, there are crawlers dedicated to it. On a private repo they're exposed to every collaborator, every fork, and every future access-scope mistake.

**Detect:** `git ls-files | grep -E '(^|/)\.env'` finds it tracked now. `git log --all --diff-filter=A --name-only -- '*.env*'` finds it ever committed — that matters even if it was later deleted, because git keeps it. Also check `.gitignore` actually covers `.env*`, and watch for the near-misses that slip through: `.env.production`, `.env.local.bak`, `config.json` with real values, a `docker-compose.yml` with inline passwords, a committed `terraform.tfvars`.

**False positive:** `.env.example` / `.env.template` with placeholder values is correct practice — that's how the next developer knows what to set. Confirm the values are actually placeholders before waving it through.

**Fix, in this order:** (1) **rotate every key in the file** — this is the actual fix and everything else is cleanup; (2) `git rm --cached .env` and add it to `.gitignore`; (3) optionally scrub history with `git filter-repo` or BFG, noting this rewrites history and breaks everyone's clone. Never present step 2 as sufficient.

### [2] API keys shipped to the browser

**What:** Any secret in client code is public. Minification is not obfuscation; "it's in an env var" doesn't help if the bundler inlines it.

**Detect:** Env vars with a public prefix — `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `EXPO_PUBLIC_*`, `PUBLIC_*` (SvelteKit), `GATSBY_*` — are inlined into the bundle by design. Any of those whose name contains `SECRET`, `SERVICE_ROLE`, `PRIVATE`, or an admin-sounding word is a finding. Also grep client directories for literal key shapes: `sk_live_`, `sk-`, `AKIA`, `ghp_`, `AIza`, `xoxb-`, `service_role`, and long `eyJ...` JWTs. If a build directory exists, grep the built output — that's ground truth for what actually ships.

**False positive — the important one:** publishable keys are *supposed* to be there. Supabase anon keys, Firebase `apiKey`, Stripe `pk_live_`, PostHog and analytics keys are designed for the browser and their safety comes from server-side rules, not secrecy. Flagging them as exposed secrets is the signature move of an audit that didn't read the docs. When you see one, don't report the key — go check the rules that make it safe (see section B) and report *those* if they're missing.

**Fix:** Move the call server-side — a route handler, an edge function, a backend endpoint the browser calls instead. The browser asks your server; your server holds the key. Then rotate the exposed key, since it's been public.

---

## B. Authorization that isn't enforced server-side

This section contains the findings most likely to be catastrophic. Weight it accordingly.

### [3] No row-level security

**What:** When the browser talks to the database directly (Supabase, Firebase, and similar), the anon key is a *door*, not a lock. Row-level security policies are the lock. Without them, anyone who opens devtools, copies the key from your bundle, and points a client at your project reads and writes every row in every table.

This is the single most common way an AI-assisted app leaks its entire user table, and it is completely invisible from the front end — the app looks and behaves perfectly.

**Detect and fix:** see `references/supabase-firebase.md`, which has the full verification procedure. Do not conclude "RLS is on" from a migration file alone; verify against the live project when you can.

### [4] Permissions enforced only in the front end

**What:** The UI hides the button; the endpoint still answers. An attacker never sees your UI.

**Detect:** Look for authorization decisions that live in components, route guards, or conditional rendering — `if (user.role === 'admin')` wrapping JSX, a `<ProtectedRoute>` with no server counterpart, a nav item filtered by role. Then find the endpoint or database call behind that button and ask: **if I call this directly with a normal user's token, what stops me?** If the answer is only the UI, that's the finding.

The reliable method is to work backwards from the most dangerous action in the app — delete account, change role, issue refund, export data — and trace what actually gates it on the server.

**False positive:** Client checks alongside real server checks are good practice — they make the UI coherent. The finding is the *absence of the server check*, not the presence of the client one.

**Fix:** Enforce on the server, at the point of data access, using identity derived from the verified session — never from a request field. Keep the client check for UX.

### [11] Unauthenticated admin panel

**What:** `/admin` returns the dashboard to anyone who types the URL. Extremely common, because the admin surface is usually built last and locally, where the developer is always logged in.

**Detect:** Enumerate admin-ish routes — `/admin`, `/dashboard`, `/internal`, `/debug`, `/_next/...`, Django admin, Adminer, Swagger/OpenAPI explorers, Prisma Studio, database GUIs. Check each one's server-side auth. Obscurity of the path counts for nothing; assume it's known.

**Fix:** Real authentication plus an explicit role check on the server, applied to the admin *API routes* and not just the page. Rendering a login form while the underlying data endpoints stay open is a common half-fix.

### [14] Predictable IDs

**What:** Sequential integers let an attacker walk your data — `/invoice/1041` implies `/invoice/1040`. This is only a vulnerability when combined with a missing ownership check, but the combination is very common, and the predictability turns a single-record bug into a full export.

**Detect:** Auto-increment primary keys exposed in URLs or API responses. Then check the fetch: does it filter by owner, or only by ID? `where id = ?` without `and user_id = ?` is the finding.

**Fix:** The ownership check is the real fix — always scope queries to the authenticated user. UUIDs are defense in depth that make enumeration impractical, but they are not authorization; don't accept a UUID migration as closing the hole.

---

## C. Input treated as trustworthy

### [6] SQL built by string concatenation

**What:** User input spliced into a query becomes query *syntax*. Classic injection: read any table, drop any table.

**Detect:** Template literals or `+` inside `query()`, `execute()`, `raw()`, `$queryRawUnsafe`, `.rpc()` with interpolated SQL. ORMs are usually safe by default — the danger is their explicit escape hatches, so search for those by name.

**False positive:** Interpolating a value you constructed yourself (a constant, an integer you just validated) is not injectable. Confirm the input's origin before reporting; trace it to a request field or don't report it.

**Fix:** Parameterized queries — `where id = $1` with the value passed separately. If an identifier (table or column name) genuinely must be dynamic, validate it against a hardcoded allowlist; it cannot be parameterized.

### [7] No input validation

**What:** Endpoints accepting arbitrary shapes and types. Rarely the whole exploit on its own; usually the enabler for another one, and a reliable source of crashes and corrupt data.

**Detect:** Handlers that read `req.body.x` with no schema in between. Look for whether *any* validation library is in the dependency list at all (zod, yup, joi, pydantic, class-validator) — if none is, that's the finding for the whole app rather than per-endpoint.

**Fix:** Parse the body against a schema at the top of each handler and reject what doesn't match. Validate on the server even if you already validate on the client; the client's copy is a convenience for the user, not a control.

### [8] User content rendered as raw HTML

**What:** Stored XSS. Attacker puts a `<script>` in a display name or comment; it runs in every other user's browser with their session.

**Detect:** `dangerouslySetInnerHTML`, `.innerHTML =`, `v-html`, `{@html}` in Svelte, `|safe` / `mark_safe` in Django/Jinja, `html.raw` in Rails. For each, trace the data backwards to its source.

**False positive:** A hardcoded constant, or output from a sanitizer like DOMPurify, or trusted server-rendered markup. The source is what matters, not the sink.

**Fix:** Render as text — every modern framework escapes by default, so the fix is usually deleting the escape hatch. Where HTML genuinely must be supported (a rich-text editor), sanitize with DOMPurify or an equivalent allowlist sanitizer on the *server*, and store the sanitized version.

### [15] Saving the whole request body (mass assignment)

**What:** `db.update(req.body)` lets the caller write fields you never meant to expose. The canonical exploit: `{"name":"x","role":"admin"}` or `{"credits":999999}` or `{"is_verified":true}`. Cheap to exploit, frequently catastrophic, and almost invisible in review because the line of code looks tidy.

**Detect:** Spreads or direct passthrough of request bodies into database writes — `{...req.body}`, `Object.assign(user, req.body)`, `Model(**request.json)`, `update(req.body)`. Also check `SELECT *`-style responses returning columns the client shouldn't see (password hashes, internal flags, other users' emails).

**Fix:** Allowlist the writable fields explicitly — pick the fields you accept rather than excluding the ones you don't, because a denylist silently fails open the next time someone adds a column. A validation schema with `strict` mode gives you this for free.

### [20] Unvalidated file uploads

**What:** Depending on where files land: stored XSS via SVG or HTML, storage exhaustion, malware distribution from your domain, or remote code execution if uploads land somewhere executable.

**Detect:** Upload handlers with no size cap, no type check, or a type check based on the `Content-Type` header or file extension — both are attacker-supplied and mean nothing. Check where files are stored and whether that path is publicly served.

**Fix:** Cap size, verify the actual file signature (magic bytes) rather than the claimed type, generate your own filename instead of using theirs, store outside the web root or in object storage, and serve from a separate domain or with `Content-Disposition: attachment` so the browser won't execute what it gets.

---

## D. Identity and sessions

### [9] Passwords stored in plain text or weakly hashed

**What:** One database leak becomes a credential-stuffing campaign against every other service your users use.

**Detect:** A `password` column written without hashing; MD5 or SHA-1 or SHA-256 used directly; a homemade hash. Fast general-purpose hashes are the subtle version of this bug — they're built for speed, which is precisely wrong here.

**False positive:** Managed auth (Supabase Auth, Auth0, Clerk, NextAuth, Firebase Auth) handles this. If the app uses one, the check is simply that no parallel homemade password path exists alongside it.

**Fix:** bcrypt, scrypt, or Argon2 with sane cost parameters. Better: don't store passwords — use a managed auth provider.

### [10] Auth tokens in localStorage

**What:** `localStorage` is readable by any JavaScript on the page, so any XSS becomes full account takeover, and it persists. Real but frequently overstated: if you have XSS, an attacker has plenty of options regardless. Report it as hardening, not as critical, unless you also found an XSS sink in section C — in which case the two together are a genuine chain and should be reported as one finding.

**Detect:** `localStorage.setItem('token'...)`, `sessionStorage` holding a JWT, tokens in non-httpOnly cookies.

**False positive:** Many auth SDKs (including Supabase's) use localStorage by design and are explicit about the tradeoff. Note it, don't alarm.

**Fix:** `httpOnly`, `Secure`, `SameSite=Lax` cookies, so JavaScript cannot read the token at all. Keep tokens short-lived with refresh.

### [13] No email verification

**What:** Signup with addresses the user doesn't own. Enables impersonation, spam relay through your transactional email (which wrecks your sending reputation), and abuse of anything you grant on signup — free credits, trial API calls, invites.

**Detect:** Whether the signup flow gates any capability on a verified flag. If the app grants anything costly on signup, weight this higher.

**Fix:** Verification link before granting anything that costs you money or is visible to other users.

### [19] No password strength requirements

**What:** `123456` passes. Low severity on its own; matters most when combined with no rate limiting (see [5]), which together make credential stuffing trivially cheap.

**Fix:** Minimum length over composition rules — length is what actually helps, and forced symbols push users to predictable patterns. Check against a breached-password list (Have I Been Pwned's range API) if you want the highest-value single control here.

---

## E. Boundary and operational config

### [5] No rate limiting

**What:** Unlimited requests enable credential stuffing, scraping, and cost amplification. The last one is now the most urgent version for small apps: an unauthenticated endpoint that calls a paid LLM or SMS API is an open tap on your card, and this bites people faster than any data breach.

**Detect:** Whether *any* rate limiting exists — middleware, an `@upstash/ratelimit`, a platform WAF rule, a gateway config. Then check specifically: login, signup, password reset, and every endpoint that costs money per call.

**Detection caveat worth reporting honestly:** rate limiting is often configured at the CDN or hosting platform and is genuinely invisible in the repo. If you can't see it, say you couldn't see it and name where to look — don't report absence you didn't establish.

**Fix:** Limit by IP and by account on auth routes; limit paid endpoints per authenticated user; require auth before anything expensive.

### [12] CORS set to `*`

**What:** Allows any origin to call your API from a victim's browser. Materially dangerous when combined with cookie auth — a malicious page can then make authenticated requests as your logged-in user. Note that browsers refuse to combine `Access-Control-Allow-Origin: *` with credentials, so the genuinely dangerous pattern is the one that *reflects* the request's origin back while allowing credentials.

**Detect:** `origin: '*'`, `cors()` with no options, `Access-Control-Allow-Origin: *`, and especially `origin: req.headers.origin` together with `credentials: true`.

**False positive:** A truly public, unauthenticated, read-only API is fine with `*`. Severity here is a function of what the API does, so check that before rating it.

**Fix:** An explicit allowlist of your own origins. If credentials are involved, never reflect an arbitrary origin.

### [16] Webhook handlers that don't verify signatures

**What:** The endpoint is public and the payload is attacker-controllable. Without signature verification anyone can POST `{"type":"payment.succeeded"}` and get whatever your handler grants — paid plans, credits, unlocked features. Free money, and the logs look like a normal payment.

**Detect:** Handlers under `/webhook`, `/api/webhooks/*`, or named for a provider (`stripe`, `github`, `clerk`, `shopify`, `twilio`) that parse the body without calling a verification function. In Stripe's case that's `stripe.webhooks.constructEvent` with the raw body and the signing secret; other providers have equivalents. A handler that reads `req.body` as parsed JSON often *cannot* verify, since verification needs the raw bytes — that's a useful tell.

**Fix:** Verify with the provider's library and the signing secret before touching the payload, using the raw request body. Reject on failure. Treat the event's ID as an idempotency key so replays don't double-apply.

### [17] Stack traces in production

**What:** Error pages leaking file paths, framework versions, SQL, and sometimes credentials from connection strings. Not directly exploitable; a reliable accelerant for everything else.

**Detect:** `DEBUG = True`, `app.debug`, error handlers returning `err.stack` or `err.message` to the client, verbose error pages in the production config.

**Fix:** Generic message plus a reference ID to the client; full detail to your logs.

### [18] Outdated dependencies

**What:** Known CVEs in what you shipped. This is the one class with genuinely good automated tooling, so it's cheap to be thorough.

**Detect:** `npm audit`, `pip-audit`, `cargo audit`, or the equivalent. Check whether Dependabot or Renovate is configured. Focus on what's actually reachable and network-facing — a critical CVE in a build-time dev dependency usually isn't the emergency the tool's colour-coding implies, and saying so builds credibility for the ones that are.

**Fix:** Patch reachable vulnerabilities; enable automated dependency updates so this doesn't need a human.
