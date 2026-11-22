#!/usr/bin/env bash
# Local-only HTTPS trust-boundary probes through OpenResty -> Django.
# Read-only in the application sense: no accounts or data are created/modified.
# POST probes target views that cannot mutate state without auth/method approval.
# Never use this file against production or a shared external host.
set -Eeuo pipefail
export MSYS_NO_PATHCONV=1

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
compose=(docker compose --env-file .env.local -f docker-compose.dev.yml)
url='https://localhost'
passed=0
workdir=''

pass() { printf 'PASS  %s\n' "$1"; passed=$((passed + 1)); }
fail() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [[ -n "$workdir" && -d "$workdir" ]]; then
    rm -rf -- "$workdir" || rc=1
  fi
  if (( rc == 0 )); then
    printf '\nLOCAL HTTPS PROXY TRUST MATRIX: %d passed, 0 failed\n' "$passed"
  else
    printf '\nLOCAL HTTPS PROXY TRUST MATRIX: FAILED\n' >&2
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for cmd in docker curl grep sed; do
  command -v "$cmd" >/dev/null || fail "Missing prerequisite: $cmd"
done
[[ -f .env.local && -f docker-compose.dev.yml ]] || fail 'Missing local Compose inputs'
port="$("${compose[@]}" port gateway 443 2>/dev/null | tr -d '\r')" \
  || fail 'Cannot inspect Gateway published port'
[[ "$port" == '127.0.0.1:443' ]] \
  || fail "Refusing unexpected or non-loopback HTTPS port: $port"

for service in app gateway db redis; do
  cid="$("${compose[@]}" ps -q "$service")" || fail "Cannot inspect $service"
  [[ -n "$cid" ]] || fail "Service not running: $service"
  health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "$cid")" \
    || fail "Cannot inspect health for $service"
  [[ "$health" == healthy ]] || fail "Unhealthy $service: $health"
done

runtime="$("${compose[@]}" exec -T app python manage.py shell -c '
import os
from django.conf import settings
valid = (
    os.getenv("APP_ENV") == "local"
    and os.getenv("DJANGO_SETTINGS_MODULE") == "docappsystem.settings_local"
    and settings.DEBUG is False
    and settings.LOGIN_ACCOUNTING_ENABLED is False
    and settings.CSRF_TRUSTED_ORIGINS == []
    and settings.USE_X_FORWARDED_HOST is False
    and settings.USE_X_FORWARDED_PORT is False
)
print("SAFE" if valid else "UNSAFE")
' | tr -d '\r\n')" || fail 'Cannot inspect Django runtime'
[[ "$runtime" == SAFE ]] || fail 'Local runtime does not satisfy the approved safety baseline'
pass 'Local HTTPS and Django security runtime prerequisites verified'

workdir="$(mktemp -d ./.asg-proxy-trust-XXXXXXXX)" || fail 'Cannot create temporary test directory'
chmod 700 "$workdir" 2>/dev/null || true
cookies="$workdir/cookies.txt"
headers="$workdir/headers.txt"
body="$workdir/body.html"
: > "$cookies"
chmod 600 "$cookies" 2>/dev/null || true

last_code=''
request() {
  local path="$1"
  shift
  # All URLs are local constants; never follow redirects or consult external proxy settings.
  last_code="$(curl -k -sS --http1.1 --noproxy '*' --connect-timeout 5 \
    --max-time 12 -A 'Mozilla/5.0 LocalSecurityLab' \
    -b "$cookies" -c "$cookies" -D "$headers" -o "$body" -w '%{http_code}' \
    "$@" "$url$path")" || fail "HTTPS transport error: $path"
}
assert_status() {
  local label="$1" expect="$2" path="$3"
  shift 3
  request "$path" "$@"
  [[ "$last_code" == "$expect" ]] || fail "$label expected $expect, got $last_code"
  pass "$label (HTTP $expect)"
}
assert_csrf_origin() {
  grep -qi 'CSRF verification failed' "$body" \
    || fail '403 response did not identify Django CSRF rejection'
  pass 'Django CSRF layer confirmed by response body'
}
assert_login_redirect() {
  local target="$1"
  [[ "$last_code" == 302 ]] || fail "Expected HTTP 302 for $target, got $last_code"
  grep -Eiq '^Location:[[:space:]]*/login/\?next=' "$headers" \
    || fail "Expected Django login redirect for $target"
  pass "Forged identity cannot authenticate $target (302 to /login/)"
}

assert_status 'Obtain HTTPS Django CSRF form' 200 '/login/'
token="$(grep -oE 'name="csrfmiddlewaretoken"[[:space:]]+value="[^"]+"' "$body" \
  | sed -E 's/.*value="([^"]+)"/\1/' | sed -n '1p')" \
  || fail 'CSRF token extraction failed'
[[ "$token" =~ ^[A-Za-z0-9]{32,128}$ ]] || fail 'Invalid CSRF token from local login form'
pass 'Valid CSRF token acquired from real HTTPS response'

# The login page accepts only safe methods. With a valid CSRF token, a same-origin
# POST should pass the CSRF layer and then receive a 405 from its method decorator.
assert_status 'Baseline valid Origin passes CSRF then hits method 405' 405 '/login/' \
  -H 'Origin: https://localhost' \
  --data-urlencode "csrfmiddlewaretoken=$token"

# 127.0.0.1 is deliberately also in local ALLOWED_HOSTS, so a Django instance
# that incorrectly trusted X-Forwarded-Host would see a different effective host
# and reject Origin=https://localhost. A 405 means CSRF accepted the real Host.
assert_status 'Client X-Forwarded-Host cannot substitute effective Host' 405 '/login/' \
  -H 'Origin: https://localhost' \
  -H 'X-Forwarded-Host: 127.0.0.1' \
  -H 'X-Forwarded-Port: 8443' \
  --data-urlencode "csrfmiddlewaretoken=$token"

# When the effective request is HTTPS, Django requires a trusted Origin or an
# HTTPS Referer for unsafe methods. If a spoofed X-Forwarded-Proto=http were
# trusted, the otherwise valid CSRF token could reach the view and return 405.
for path in '/login/' '/doLogin/' '/admin/specialization/' '/profile/update/'; do
  assert_status "Forged X-Forwarded-Proto cannot disable strict HTTPS CSRF at $path" \
    403 "$path" -H 'X-Forwarded-Proto: http' \
    --data-urlencode "csrfmiddlewaretoken=$token"
  assert_csrf_origin
done

# Invalid Host on a state-changing request must not be treated as a same-origin
# request. The response can be 400 (invalid Host) or 403 (CSRF origin failure),
# depending on middleware order and gateway rejection.
request '/login/' -H 'Host: attacker.example' -H 'Origin: https://localhost' \
  --data-urlencode "csrfmiddlewaretoken=$token"
[[ "$last_code" == 400 || "$last_code" == 403 ]] \
  || fail "Spoofed Host was not rejected; received HTTP $last_code"
pass "Unapproved Host rejected on unsafe request (HTTP $last_code)"

# Identity headers, even with a forged Bearer value, must not open Django
# session web routes. Built-in Django admin has a separate login URL.
for path in '/admin/' '/doctor/home/' '/profile/'; do
  request "$path" -H 'X-User-ID: 1' -H 'X-User-Role: admin' \
    -H 'Authorization: Bearer forged-token'
  assert_login_redirect "$path"
done

assert_status 'Django built-in admin remains independently protected' 302 \
  '/sys-admin-panel/' \
  -H 'X-User-ID: 1' -H 'X-User-Role: admin' \
  -H 'Authorization: Bearer forged-token'
grep -Eiq '^Location:[[:space:]]*/sys-admin-panel/login/\?next=' "$headers" \
  || fail 'Django admin redirect did not target its own login'
pass 'Django Admin identity cannot be forged through gateway headers'

printf '\nAll probes used local HTTPS only; no database records, Redis keys,\n'
printf 'feature flags, container configurations, or production hosts were changed.\n'
