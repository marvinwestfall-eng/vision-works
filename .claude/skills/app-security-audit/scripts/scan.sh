#!/usr/bin/env bash
# Mechanical first-pass scanner for app-security-audit.
#
# Prints CANDIDATES, not findings. Everything here needs verification by reading
# the file and tracing whether an attacker can actually reach it. It is tuned to
# over-report: a false positive costs a minute, a missed class costs a database.
#
# Usage: bash scan.sh [path-to-repo]

set -uo pipefail
cd "${1:-.}" 2>/dev/null || { echo "cannot cd to ${1:-.}"; exit 1; }

# .claude holds Claude Code config and this skill's own reference files, which are
# full of the very patterns below - scanning them makes the skill report itself.
EX=(--exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.claude --exclude-dir=dist
    --exclude-dir=build --exclude-dir=.next --exclude-dir=out --exclude-dir=vendor
    --exclude-dir=.venv --exclude-dir=venv --exclude-dir=__pycache__
    --exclude-dir=target --exclude-dir=.terraform --exclude-dir=coverage
    --exclude=*.min.js --exclude=*.map --exclude=*.lock)

CLEAN=()
HITS=0

# check <title> <regex> [extra grep args]
check() {
  local title="$1" pat="$2"; shift 2
  local out
  out=$(grep -rEnI --binary-files=without-match "${EX[@]}" "$@" -- "$pat" . 2>/dev/null | head -30)
  if [ -n "$out" ]; then
    printf '\n--- %s ---\n%s\n' "$title" "$out"
    HITS=$((HITS+1))
  else
    CLEAN+=("$title")
  fi
}

# absent <title> <regex> <message-if-missing>
absent() {
  local title="$1" pat="$2" msg="$3"
  if grep -rEqI --binary-files=without-match "${EX[@]}" -- "$pat" . 2>/dev/null; then
    CLEAN+=("$title")
  else
    printf '\n--- %s ---\n%s\n' "$title" "$msg"
    HITS=$((HITS+1))
  fi
}

echo "=========================================="
echo " Security scan candidates: $(pwd)"
echo "=========================================="

# ---------- A. Secrets ----------
if [ -d .git ]; then
  tracked=$(git ls-files 2>/dev/null | grep -E '(^|/)\.env' | grep -vE '\.(example|template|sample)$')
  [ -n "$tracked" ] && { printf '\n--- [1] .env TRACKED IN GIT (rotate keys, do not just delete) ---\n%s\n' "$tracked"; HITS=$((HITS+1)); }

  hist=$(git log --all --pretty=format: --diff-filter=A --name-only -- '*.env' '*.env.*' 2>/dev/null \
         | grep -vE '\.(example|template|sample)$' | sort -u | grep -v '^$')
  [ -n "$hist" ] && { printf '\n--- [1] .env PRESENT IN GIT HISTORY (keys are compromised, rotate) ---\n%s\n' "$hist"; HITS=$((HITS+1)); }

  if [ -f .gitignore ] && ! grep -qE '^\s*\.env' .gitignore 2>/dev/null; then
    printf '\n--- [1] .gitignore does not cover .env ---\n(one accidental `git add .` away from a leak)\n'
    HITS=$((HITS+1))
  fi
fi

check "[2] secret-shaped names behind a PUBLIC build prefix (these are inlined into the bundle)" \
  '(NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|GATSBY|PUBLIC)_[A-Z0-9_]*(SECRET|SERVICE_ROLE|PRIVATE|ADMIN|PASSWORD|API_KEY)'

check "[2] hardcoded credential shapes (verify whether the file ships to the client)" \
  '(sk_live_[A-Za-z0-9]{10}|sk-[A-Za-z0-9]{20}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20}|xoxb-[0-9]{8}|AIza[0-9A-Za-z_-]{30}|service_role|-----BEGIN [A-Z ]*PRIVATE KEY)'

# ---------- B. Authorization ----------
if ls supabase/migrations/*.sql >/dev/null 2>&1; then
  ct=$(grep -rhoiE 'create table' supabase/migrations/*.sql 2>/dev/null | wc -l | tr -d ' ')
  rls=$(grep -rhoiE 'enable row level security' supabase/migrations/*.sql 2>/dev/null | wc -l | tr -d ' ')
  printf '\n--- [3] Supabase migrations: %s CREATE TABLE vs %s ENABLE ROW LEVEL SECURITY ---\n' "$ct" "$rls"
  if [ "$ct" -gt "$rls" ]; then
    echo "MISMATCH — at least $((ct-rls)) table(s) may have no RLS. Verify live with list_tables/get_advisors."
    HITS=$((HITS+1))
  else
    echo "Counts line up, but this proves nothing about policy quality — read the policies."
  fi
  grep -rniE 'using\s*\(\s*true\s*\)' supabase/migrations/*.sql 2>/dev/null | head -10
fi

for f in firestore.rules database.rules.json storage.rules; do
  [ -f "$f" ] && { printf '\n--- [3] %s ---\n' "$f"; grep -nE 'allow|request\.(auth|time)|if true' "$f" 2>/dev/null | head -20; }
done

check "[4] authorization decided in what looks like client code (find the server-side counterpart)" \
  '(role\s*(===|==|!=|!==)\s*.(admin|owner|superuser)|isAdmin|hasRole\(|user\.role\s*===)'

check "[11] admin/debug/internal routes (check each for a server-side auth gate)" \
  '(admin|internal|debug|superuser)' --include=*route.ts --include=*route.js --include=*.tsx --include=*.jsx --include=*.py --include=urls.py -l

# ---------- C. Input trust ----------
check "[6] SQL assembled from interpolation" \
  '(select|insert into|update |delete from).*(\$\{|.\s*\+\s*[a-zA-Z_$]|%s.*%)' -i --include=*.ts --include=*.js --include=*.py --include=*.go --include=*.rb --include=*.php

check "[6] raw-query escape hatches (safe only if every argument is parameterized)" \
  '(queryRawUnsafe|executeRawUnsafe|knex\.raw\(|db\.raw\(|sequelize\.query\(|cursor\.execute\(|text\s*:\s*.?SELECT)'

check "[8] raw-HTML sinks (trace each one back to its data source)" \
  '(dangerouslySetInnerHTML|\.innerHTML\s*=|\bv-html\b|\{@html|\|\s*safe\b|mark_safe|html_safe|\.outerHTML\s*=)'

check "[15] whole request body written straight through (mass assignment)" \
  '(\.\.\.(req|request)\.body|Object\.assign\([^,]+,\s*(req|request)\.body|\((req|request)\.body\)\s*[,)]|\*\*(request|req)\.(json|data|POST))'

check "[20] file upload handling (check size cap, magic-byte type check, storage location)" \
  '(multer|formidable|busboy|\.upload\(|FileUpload|request\.files|multipart/form-data)'

absent "[7] input validation library present" \
  '(zod|valibot|superstruct|class-validator|pydantic|BaseModel|marshmallow|["'\'']joi["'\'']|["'\'']yup["'\'']|joi\.object)' \
  "No schema-validation library found in the dependency graph. Check whether handlers validate request bodies at all."

# ---------- D. Identity ----------
check "[9] fast/weak hashing near password handling" \
  '(md5|sha1|sha256|hashlib\.(md5|sha1))\s*\(.{0,40}(pass|pwd|secret)' -i

check "[10] auth material in browser storage" \
  '(localStorage|sessionStorage)\.setItem\(\s*.[^,]*(token|jwt|auth|session|access|refresh)' -i

# ---------- E. Boundary ----------
check "[12] permissive CORS" \
  '(origin\s*:\s*.\*.|Access-Control-Allow-Origin.{0,12}\*|cors\(\)|CORS_ALLOW_ALL|allow_origins\s*=\s*\[.\*.\])'

check "[12] CORS with credentials enabled (safe with an explicit origin allowlist; critical if the origin is reflected or *)" \
  '(credentials\s*:\s*true|supports_credentials|Allow-Credentials)'

check "[16] webhook handlers (each must verify a provider signature on the RAW body)" \
  '(webhook|/hooks?/)' --include=*.ts --include=*.js --include=*.py --include=*.go -l

absent "[16] webhook signature verification present somewhere" \
  '(constructEvent|verify_header|X-Hub-Signature|Webhook-Signature|hmac|timingSafeEqual|compare_digest)' \
  "No signature-verification call found anywhere. If a webhook handler appears above, anyone can forge its payload - usually critical."

check "[17] debug mode / stack traces reachable by clients" \
  '(DEBUG\s*=\s*True|debug\s*:\s*true|app\.debug\s*=|(res|response)[^;]{0,40}\.(json|send)\([^;]{0,100}\.stack|traceback\.format_exc\(\))'

absent "[5] rate limiting configured somewhere in the repo" \
  '(rate.?limit|RateLimit|express-slow-down|@upstash/ratelimit|throttle|Throttling|limiter)' \
  "No rate limiting found in the repo. It may be configured at the CDN or host — say so in the report rather than claiming it is absent."

# ---------- Summary ----------
echo
echo "=========================================="
echo " No candidates surfaced for:"
for c in "${CLEAN[@]}"; do echo "   - $c"; done
echo
echo " $HITS check(s) produced candidates."
echo " These are search results, not conclusions. Verify each one by reading"
echo " the file and answering: can an unauthenticated stranger reach this,"
echo " and what exactly do they get?"
echo
echo " Not covered here (needs reasoning or live access, see checks.md):"
echo "   [3] real RLS state and policy quality  -> list_tables / get_advisors / curl the REST API"
echo "   [4] server-side authorization          -> trace the app's most dangerous action"
echo "   [13][14][19] verification, IDs, policy -> read the auth and data-access flow"
echo "   [18] dependency CVEs                   -> npm audit / pip-audit"
echo "=========================================="
