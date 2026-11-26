#!/usr/bin/env bash
# Local-only HTTPS regression for CSRF, session authentication, request methods,
# and reverse-proxy trust boundaries through OpenResty and Django.
#
# Preconditions:
# - Local Docker Compose services are healthy and bound to 127.0.0.1.
# - Account-aware login accounting is disabled in the local runtime.
# - A disposable account can be created in the local MySQL database.
#
# This test never targets production, toggles feature flags, deletes Redis keys,
# or recreates containers. It removes only its own disposable database account.
set -Eeuo pipefail
export MSYS_NO_PATHCONV=1

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
compose=(docker compose --env-file .env.local -f docker-compose.dev.yml)
url='https://localhost'
passed=0
fixture_attempted=0
fixture_id=''
workdir=''

email="asg-auth-e2e-$(date +%s)-$RANDOM@example.invalid"
username="asg_auth_e2e_$(date +%s)_${RANDOM}"
password="AuthE2E!$(date +%s)${RANDOM}${RANDOM}"

pass() {
    printf 'PASS  %s\n' "$1"
    passed=$((passed + 1))
}
fail() {
    printf 'FAIL  %s\n' "$1" >&2
    exit 1
}

cleanup() {
    local result=$?
    trap - EXIT INT TERM
    set +e

    if (( fixture_attempted == 1 )); then
        # Exact-match deletion only. No prefix scan and no broad account deletion.
        "${compose[@]}" exec -T \
            -e "ASG_AUTH_E2E_EMAIL=$email" \
            -e "ASG_AUTH_E2E_USERNAME=$username" \
            -e "ASG_AUTH_E2E_ID=$fixture_id" \
            app python manage.py shell -c '
import os
from django.contrib.auth import get_user_model
mail = os.environ["ASG_AUTH_E2E_EMAIL"]
name = os.environ["ASG_AUTH_E2E_USERNAME"]
uid = os.environ.get("ASG_AUTH_E2E_ID", "")
assert name.startswith("asg_auth_e2e_")
assert mail.startswith("asg-auth-e2e-") and mail.endswith("@example.invalid")
qs = get_user_model().objects.filter(
    email=mail, username=name, user_type="1", is_active=True,
)
if uid:
    assert uid.isdecimal()
    qs = qs.filter(pk=int(uid))
assert qs.count() <= 1, "Refusing ambiguous fixture cleanup"
if qs.exists():
    qs.delete()
    print("LOCAL TEST ACCOUNT: REMOVED")
else:
    print("LOCAL TEST ACCOUNT: NOT PRESENT")
' || {
            echo 'CRITICAL: Local test-account cleanup failed; inspect only the generated fixture.' >&2
            result=1
        }
    fi

    if [[ -n "$workdir" && -d "$workdir" ]]; then
        rm -rf -- "$workdir" || result=1
    fi

    if (( result == 0 )); then
        printf '\nLOCAL HTTPS SECURITY REGRESSION: %d passed, 0 failed\n' "$passed"
    else
        echo 'LOCAL HTTPS SECURITY REGRESSION: FAILED; inspect the local fixture cleanup.' >&2
    fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

command -v docker >/dev/null || fail 'Docker CLI is required'
command -v curl >/dev/null || fail 'curl is required'
command -v grep >/dev/null || fail 'grep is required'
command -v sed >/dev/null || fail 'sed is required'
[[ -f .env.local && -f docker-compose.dev.yml ]] || fail 'Local Compose configuration is missing'

port="$("${compose[@]}" port gateway 443 2>/dev/null | tr -d '\r')" || fail 'Cannot inspect the local HTTPS gateway port'
[[ "$port" == '127.0.0.1:443' ]] || fail "Refusing non-loopback or unexpected HTTPS binding: $port"

for service in app gateway db redis; do
    cid="$("${compose[@]}" ps -q "$service")" || fail "Cannot inspect service: $service"
    [[ -n "$cid" ]] || fail "Local service is not running: $service"
    state="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing-healthcheck{{end}}' "$cid")" \
        || fail "Cannot inspect health: $service"
    [[ "$state" == 'healthy' ]] || fail "Local service $service is not healthy: $state"
done

runtime="$("${compose[@]}" exec -T app python manage.py shell -c '
import os
from django.conf import settings
checks = (
    os.getenv("APP_ENV") == "local",
    os.getenv("DJANGO_SETTINGS_MODULE") == "docappsystem.settings_local",
    settings.DEBUG is False,
    settings.LOGIN_ACCOUNTING_ENABLED is False,
    settings.USE_X_FORWARDED_HOST is False,
    settings.USE_X_FORWARDED_PORT is False,
    settings.CSRF_TRUSTED_ORIGINS == [],
)
print("LOCAL_SECURITY_READY" if all(checks) else "LOCAL_SECURITY_NOT_READY")
' | tr -d '\r\n')" || fail 'Cannot validate local Django settings'
[[ "$runtime" == 'LOCAL_SECURITY_READY' ]] || fail 'Runtime flags/settings are not the expected local security baseline'
pass 'Healthy loopback-only local runtime and safe security settings'

# Relative paths keep curl cookie/header files portable in Windows Git Bash,
# including when MSYS path conversion is disabled for Docker arguments.
workdir="$(mktemp -d ./.asg-auth-e2e-XXXXXXXX)" || fail 'Cannot create a private temporary directory' 
chmod 700 "$workdir" 2>/dev/null || true
cookies="$workdir/cookies.txt"
headers="$workdir/headers.txt"
body="$workdir/body.html"
: > "$cookies"
chmod 600 "$cookies" 2>/dev/null || true

last_status=''
http() {
    local path="$1"
    shift
    # Never follow redirects automatically: exact status codes are part of the contract.
    last_status="$(curl -k -sS --http1.1 --noproxy '*' \
        --connect-timeout 5 --max-time 15 \
        -A 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36' \
        -b "$cookies" -c "$cookies" \
        -D "$headers" -o "$body" -w '%{http_code}' \
        "$@" "$url$path")" || fail "Transport failed: $path"
}
expect_status() {
    local label="$1" expected="$2" path="$3"
    shift 3
    http "$path" "$@"
    [[ "$last_status" == "$expected" ]] || fail "$label: expected HTTP $expected, got $last_status"
    pass "$label (HTTP $expected)"
}
token_from_last_response() {
    local token
    token="$(grep -oE 'name="csrfmiddlewaretoken"[[:space:]]+value="[^"]+"' "$body" \
        | sed -E 's/.*value="([^"]+)"/\1/' | sed -n '1p')" || return 1
    [[ "$token" =~ ^[A-Za-z0-9]{32,128}$ ]] || return 1
    printf '%s' "$token"
}
assert_cookie_security() {
    local name="$1" header value
    header="$(grep -i "^Set-Cookie: ${name}=" "$headers" | tail -n 1 | tr -d '\r')" \
        || fail "Expected Set-Cookie for $name"
    [[ -n "$header" ]] || fail "Missing Set-Cookie for $name"
    for value in Secure HttpOnly 'SameSite=Lax'; do
        echo "$header" | grep -Eqi "(^|;[[:space:]]*)${value}([;[:space:]]|$)" \
            || fail "Missing $value on $name cookie"
    done
    pass "$name cookie has Secure, HttpOnly and SameSite=Lax"
}
assert_django_csrf_response() {
    grep -qi 'CSRF verification failed' "$body" \
        || fail 'HTTP 403 was observed but Django CSRF rejection was not confirmed'
    pass 'Rejection response identifies Django CSRF protection'
}
assert_fixture_first_name() {
    local expected="$1" actual
    actual="$("${compose[@]}" exec -T \
        -e "ASG_AUTH_E2E_ID=$fixture_id" \
        -e "ASG_AUTH_E2E_EMAIL=$email" \
        -e "ASG_AUTH_E2E_USERNAME=$username" \
        app python manage.py shell -c '
import os
from django.contrib.auth import get_user_model
user = get_user_model().objects.get(
    pk=int(os.environ["ASG_AUTH_E2E_ID"]),
    email=os.environ["ASG_AUTH_E2E_EMAIL"],
    username=os.environ["ASG_AUTH_E2E_USERNAME"],
)
print(user.first_name)
' | tr -d '\r\n')" || fail 'Cannot verify local test account state'
    [[ "$actual" == "$expected" ]] || fail "Profile mutation check failed: expected $expected"
    pass 'Local database profile state matches the authorized change'
}

expect_status 'HTTPS login page is available' 200 '/login/'
csrf_before="$(token_from_last_response)" || fail 'Login page did not expose a valid form CSRF token'
assert_cookie_security 'csrftoken'

expect_status 'Unauthenticated profile remains session-protected' 302 '/profile/' \
    -H 'X-User-ID: 1' -H 'X-User-Role: admin' -H 'Authorization: Bearer forged-token'

expect_status 'Login form rejects POST with a valid CSRF token' 405 '/login/' \
    -H 'Origin: https://localhost' --data-urlencode "csrfmiddlewaretoken=$csrf_before"
expect_status 'Login form rejects forged forwarded host' 405 '/login/' \
    -H 'Origin: https://localhost' -H 'X-Forwarded-Host: 127.0.0.1' \
    --data-urlencode "csrfmiddlewaretoken=$csrf_before"
expect_status 'Gateway overwrites forged forwarded protocol' 405 '/login/' \
    -H 'Origin: https://localhost' -H 'X-Forwarded-Proto: http' \
    --data-urlencode "csrfmiddlewaretoken=$csrf_before"
expect_status 'Login form rejects cross-origin POST' 403 '/login/' \
    -H 'Origin: https://attacker.example' \
    --data-urlencode "csrfmiddlewaretoken=$csrf_before"
assert_django_csrf_response
expect_status 'HTTPS POST without Origin or Referer is rejected' 403 '/login/' \
    --data-urlencode "csrfmiddlewaretoken=$csrf_before"
assert_django_csrf_response
expect_status 'Invalid CSRF token is rejected' 403 '/login/' \
    -H 'Origin: https://localhost' \
    --data-urlencode 'csrfmiddlewaretoken=0000000000000000000000000000000000000000000000000000000000000000'
assert_django_csrf_response
expect_status 'GET cannot invoke login handler' 405 '/doLogin/'
expect_status 'PUT cannot invoke login handler' 405 '/doLogin/' \
    -X PUT -H 'Origin: https://localhost' -H "X-CSRFToken: $csrf_before"
expect_status 'PUT cannot become appointment-form GET' 405 '/userappointment/' \
    -X PUT -H 'Origin: https://localhost' -H "X-CSRFToken: $csrf_before"

# A synthetic, uniquely named user is created only after all pre-login probes pass.
fixture_attempted=1
fixture_id="$("${compose[@]}" exec -T \
    -e "ASG_AUTH_E2E_EMAIL=$email" \
    -e "ASG_AUTH_E2E_USERNAME=$username" \
    -e "ASG_AUTH_E2E_PASSWORD=$password" \
    app python manage.py shell -c '
import os
from django.contrib.auth import get_user_model
u = os.environ["ASG_AUTH_E2E_USERNAME"]
e = os.environ["ASG_AUTH_E2E_EMAIL"]
p = os.environ["ASG_AUTH_E2E_PASSWORD"]
assert u.startswith("asg_auth_e2e_") and e.endswith("@example.invalid")
User = get_user_model()
assert not User.objects.filter(username=u).exists()
assert not User.objects.filter(email=e).exists()
obj = User.objects.create_user(
    username=u, email=e, password=p, user_type="1", is_active=True,
)
print(obj.pk)
' | tr -d '\r\n')" || fail 'Cannot create isolated local test account'
[[ "$fixture_id" =~ ^[1-9][0-9]*$ ]] || fail 'Disposable account creation returned an invalid ID'
pass 'Disposable local account created without touching existing accounts'

expect_status 'Valid same-origin login succeeds' 302 '/doLogin/' \
    -H 'Origin: https://localhost' \
    --data-urlencode "email=$email" \
    --data-urlencode "password=$password" \
    --data-urlencode "csrfmiddlewaretoken=$csrf_before"
assert_cookie_security 'sessionid'
if grep -Eqi '^X-Login-(Status|Accounting|Alert):' "$headers"; then
    fail 'Gateway leaked an internal authentication signal header'
fi
pass 'Gateway strips internal login signal headers'

expect_status 'Authenticated session opens profile' 200 '/profile/'
csrf_after="$(token_from_last_response)" || fail 'Authenticated profile does not provide a post-login CSRF token'

expect_status 'Valid CSRF permits an authorized profile update' 302 '/profile/update/' \
    -H 'Origin: https://localhost' \
    --data-urlencode 'first_name=AuthorizedUpdate' \
    --data-urlencode 'last_name=SecurityTest' \
    --data-urlencode "email=$email" \
    --data-urlencode "username=$username" \
    --data-urlencode "csrfmiddlewaretoken=$csrf_after"
assert_fixture_first_name 'AuthorizedUpdate'

expect_status 'GET logout is rejected while authenticated' 405 '/logout/'
expect_status 'GET logout does not invalidate session' 200 '/profile/'

expect_status 'POST logout without CSRF is denied' 403 '/logout/' \
    -H 'Origin: https://localhost' --data ''
assert_django_csrf_response
expect_status 'Denied logout does not invalidate session' 200 '/profile/'

expect_status 'Cross-origin logout is denied with valid token' 403 '/logout/' \
    -H 'Origin: https://attacker.example' --data-urlencode "csrfmiddlewaretoken=$csrf_after"
assert_django_csrf_response
expect_status 'Cross-origin logout does not invalidate session' 200 '/profile/'

expect_status 'Authenticated password PATCH is rejected' 405 '/password/' \
    -X PATCH -H 'Origin: https://localhost' -H "X-CSRFToken: $csrf_after"
expect_status 'Authenticated profile update without CSRF is denied' 403 '/profile/update/' \
    -H 'Origin: https://localhost' --data-urlencode 'first_name=UnauthorizedChange'
assert_django_csrf_response
assert_fixture_first_name 'AuthorizedUpdate'

expect_status 'Authenticated POST logout with valid CSRF succeeds' 302 '/logout/' \
    -H 'Origin: https://localhost' --data-urlencode "csrfmiddlewaretoken=$csrf_after"
expect_status 'Logout invalidates authenticated session' 302 '/profile/'

printf '\nAll requests used HTTPS to loopback OpenResty; no production host was contacted.\n'
