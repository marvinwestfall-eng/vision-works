# Row-level security and database rules

Read this whenever the browser talks to the database directly — Supabase, Firebase, PocketBase, Appwrite, Nhost, or any "no backend needed" setup.

## Why this is the highest-stakes check

In a conventional app, your server is the security boundary: the browser asks, the server decides. In these stacks **the database is the security boundary**, because the browser holds a database client and talks to it directly.

That design is fine — it's the intended architecture, and the anon key is meant to be public. It works because the database is supposed to refuse unauthorized reads and writes itself. Row-level security policies *are* that refusal. Without them the anon key isn't a public key, it's a public database.

What makes this the most dangerous finding you can make is that **it is invisible from the outside.** The app looks perfect. Every screen shows the logged-in user exactly their own data, because the query said `where user_id = me`. The attacker simply doesn't send that `where` clause. Same key, same endpoint, every row.

The exploit takes about thirty seconds and needs no tools beyond what's already in the page:

```js
// paste in devtools on the app's own origin, using the key already loaded there
const { data } = await supabase.from('profiles').select('*')
// with RLS off: every row, every user, every column
```

## Verifying Supabase

Work down this list — each step is stronger evidence than the one before it. Stop when you reach one you can actually run.

**1. Live project state (strongest).** If Supabase MCP tools are connected, this is ground truth:

- `list_tables` — each table reports `rls_enabled`. Any user-data table showing `false` is a critical finding, full stop.
- `get_advisors` with `type: "security"` — Supabase's own linter flags RLS-disabled tables, `SECURITY DEFINER` views, and exposed extensions. Run it; it catches things a repo grep never will.

**2. Live behaviour.** Query the REST endpoint with the anon key and no session. What comes back is what the internet gets:

```bash
curl "$SUPABASE_URL/rest/v1/profiles?select=*" \
  -H "apikey: $ANON_KEY"
```

Rows returned to an unauthenticated request means either RLS is off or a policy is public. Either way it's a finding, and this output is the evidence to put in the report.

**3. Migrations (weakest — necessary but not sufficient).** In `supabase/migrations/*.sql`, every `create table` needs a matching:

```sql
alter table public.<name> enable row level security;
```

Absence here is strong evidence of a problem. **Presence is not proof of safety** — the table may have been altered in the dashboard since, and, more importantly, RLS enabled with no policies at all denies everything, which usually shows up as a broken app rather than a secure one. Enabled-and-empty and enabled-with-good-policies look identical in a grep.

## Policies that exist but don't protect

Finding `enable row level security` is where the audit starts, not where it ends. Read the policies themselves:

**`using (true)`** — a policy that permits everyone. Sometimes deliberate (a genuinely public table of, say, blog posts); usually a placeholder that shipped. Check what's in the table before deciding which.

**Only a `select` policy.** Policies are per-operation. A table with a read policy and nothing for `insert`, `update`, or `delete` is only half protected — and if the app appears to work, someone probably granted broad write access elsewhere to compensate. Confirm all four operations, or a `for all` policy.

**Identity that isn't the session.** `auth.uid() = user_id` is right — it compares against the verified JWT. A policy comparing against a column the client can set, or a value from the request, is decoration. Watch particularly for policies on a `profiles.id` that isn't actually keyed to `auth.users`.

**`service_role` used from the browser.** The service role key bypasses RLS entirely by design. In a server route that's correct and normal; in anything that reaches the client it makes every policy in the database irrelevant. Check which client instance each file imports — a shared `supabaseAdmin` accidentally imported into a component is a common and total failure.

**Storage buckets.** Easy to forget, since they're configured separately from tables. A public bucket serves every uploaded file to anyone with the URL, and object URLs are guessable more often than people expect. Check bucket visibility and storage policies alongside table policies — user uploads (ID documents, receipts, private images) are frequently more sensitive than the rows.

**Views and functions.** A view over an RLS-protected table does not automatically inherit protection, and `SECURITY DEFINER` functions run with the definer's rights — both are standard ways for data to escape correct policies. `get_advisors` flags these.

## Verifying Firebase

Firestore and Realtime Database rules live in `firestore.rules` / `database.rules.json`, and Storage in `storage.rules`. Read all three — Storage is the one that gets forgotten.

**The two critical patterns:**

```
// wide open — anyone with your public config, which is in your bundle
allow read, write: if true;

// "test mode" — a time bomb that is either wide open or silently expired
allow read, write: if request.time < timestamp.date(2024, 1, 1);
```

**`if request.auth != null` is weaker than it looks.** It means "any signed-in user," and if signup is open, that's anyone who registers — including an attacker, thirty seconds after they decide to. For per-user data you want ownership, not mere authentication:

```
allow read, write: if request.auth.uid == userId;
```

Also confirm the deployed rules match the repo — `firebase deploy` is a separate step from committing, so the file on disk can be much stricter than what's live.

## Writing the finding

Make it concrete and make it about *their* data. "RLS is not enabled" is abstract enough to defer. This is not:

> **Critical: the `profiles` table is readable and writable by anyone on the internet** — `supabase/migrations/0001_init.sql:12`
>
> RLS is not enabled on `profiles`, and the anon key is in the client bundle (as it's designed to be). Anyone can open devtools on your site and run `supabase.from('profiles').select('*')` to dump all 1,240 rows — including email addresses and Stripe customer IDs. The same access allows writes, so any row can be modified or deleted.
>
> **Fix:**
> ```sql
> alter table public.profiles enable row level security;
>
> create policy "own profile read" on public.profiles
>   for select using (auth.uid() = id);
> create policy "own profile write" on public.profiles
>   for update using (auth.uid() = id) with check (auth.uid() = id);
> ```
> Then re-run `get_advisors` to confirm, and check every other table in the same migration — they were created the same way.

The last sentence matters: RLS gaps are rarely isolated. If one table was created without it, audit all of them before closing the finding.
