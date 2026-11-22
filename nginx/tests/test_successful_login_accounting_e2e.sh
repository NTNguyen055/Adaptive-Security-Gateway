#!/usr/bin/env bash
# LOCAL-only valid-account V3 HTTP E2E through Gateway -> Django -> Redis.
# Creates an isolated test user in LOCAL MySQL; removes it on EXIT.
# Temporarily enables LOGIN_ACCOUNTING_ENABLED and restores it OFF on EXIT.
# This HARDENED version changes fixture cleanup and local-only runtime guards.
# It requires fresh local runtime validation before its result is accepted.
# This script must NEVER run against production or a shared environment.
set -Eeuo pipefail
export MSYS_NO_PATHCONV=1

cd "$(dirname "$0")/../../"
base=(docker compose --env-file .env.local -f docker-compose.dev.yml)
# Create the overlay only AFTER local runtime guards pass, and register its
# cleanup before any file or runtime resource is created.
overlay=''
test_compose=()
client="asg-a34-auth-$(date +%s)-${RANDOM}-$$"
client_started=0
needs_rollback=0
user_create_attempted=0
owned_keys=0
user_id=""
keys=()
passed=0
email="asg-a34-$(date +%s)-$RANDOM@example.invalid"
username="asg_a34_$(date +%s)_$RANDOM"
password="A34Safe-$(date +%s)-$RANDOM-ValidLogin"

pass() { printf 'PASS  %s\n' "$1"; passed=$((passed + 1)); }
fail() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }
redis_cli() { "${base[@]}" exec -T redis redis-cli --raw -n 0 "$@" | tr -d '\r'; }
flag() {
  "${base[@]}" exec -T app python -c \
    'from django.conf import settings; print(settings.LOGIN_ACCOUNTING_ENABLED)' \
    | tr -d '\r\n'
}
cleanup() {
  local status=$?
  local remaining=''
  trap - EXIT INT TERM
  set +e

  # The test owns this exact synthetic container name; no broad pruning.
  if (( client_started == 1 )); then
    docker rm -f "$client" >/dev/null 2>&1 || {
      echo 'CRITICAL: Failed to remove synthetic Docker client' >&2
      status=1
    }
  fi

  # Only delete keys whose absence was verified before this run.
  if (( owned_keys == 1 && ${#keys[@]} > 0 )); then
    redis_cli DEL "${keys[@]}" >/dev/null 2>&1 || {
      echo 'CRITICAL: Failed to remove owned Redis test keys' >&2
      status=1
    }
    remaining="$(redis_cli EXISTS "${keys[@]}")"
    if [[ $? -ne 0 || "$remaining" != 0 ]]; then
      echo 'CRITICAL: Owned Redis test keys could not be verified absent' >&2
      status=1
    fi
  fi

  if (( needs_rollback == 1 )); then
    echo '=== Restore local LOGIN_ACCOUNTING_ENABLED=False ==='
    "${base[@]}" up -d --no-deps --force-recreate --wait app || status=1
    "${base[@]}" up -d --no-deps --force-recreate --wait gateway || status=1
    [[ "$(flag)" == False ]] || {
      echo 'CRITICAL: Local Login Accounting V3 rollback not verified' >&2
      status=1
    }
  fi

  # A shell/transport failure after CREATE can hide stdout user_id. Look up
  # only the unique synthetic username+email+role; never delete by prefix.
  if (( user_create_attempted == 1 )); then
    "${base[@]}" exec -T \
      -e "ASG_A34_ID=$user_id" \
      -e "ASG_A34_EMAIL=$email" \
      -e "ASG_A34_NAME=$username" \
      app python manage.py shell -c '
import os
from django.contrib.auth import get_user_model
name = os.environ["ASG_A34_NAME"]
mail = os.environ["ASG_A34_EMAIL"]
assert name.startswith("asg_a34_")
assert mail.startswith("asg-a34-") and mail.endswith("@example.invalid")
qs = get_user_model().objects.filter(
    username=name,
    email=mail,
    user_type="1",
)
assert qs.count() <= 1, "Ambiguous synthetic user: refusing cleanup"
if qs.exists():
    actual_id = qs.values_list("pk", flat=True).get()
    expected_id = os.environ.get("ASG_A34_ID", "")
    if expected_id:
        assert expected_id.isdecimal() and actual_id == int(expected_id), (
            "Fixture ID mismatch: refusing cleanup"
        )
    qs.delete()
print("LOCAL A3.4 SYNTHETIC ACCOUNT: REMOVED OR ABSENT")
' || {
      echo 'CRITICAL: Synthetic account cleanup failed; inspect exact fixture' >&2
      status=1
    }
  fi

  if [[ -n "$overlay" ]]; then
    rm -f -- "$overlay" || status=1
  fi
  if (( status == 0 )); then
    printf '\nA3.4 valid-account V3 HTTP E2E: %d passed, 0 failed\n' "$passed"
  else
    echo 'A3.4 valid-account E2E failed; verify local rollback and fixture cleanup' >&2
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ -f .env.local && -f docker-compose.dev.yml ]] || fail 'Missing local stack'

# No side effects until we know the public HTTPS listener and all runtime
# dependencies belong to the expected local lab.
port="$("${base[@]}" port gateway 443 2>/dev/null | tr -d '\r')" \
  || fail 'Cannot inspect local Gateway HTTPS binding'
[[ "$port" == '127.0.0.1:443' ]] \
  || fail "Refusing non-loopback Gateway HTTPS binding: $port"
for service in app gateway db redis; do
  cid="$("${base[@]}" ps -q "$service")" || fail "Cannot inspect $service"
  [[ -n "$cid" ]] || fail "Local service not running: $service"
  health="$(docker inspect -f \
    '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing-healthcheck{{end}}' \
    "$cid")" || fail "Cannot inspect health for $service"
  [[ "$health" == healthy ]] || fail "Unhealthy local service $service: $health"
done
runtime="$("${base[@]}" exec -T app python manage.py shell -c '
import os
from django.conf import settings
safe = (
    os.environ.get("APP_ENV") == "local"
    and os.environ.get("DJANGO_SETTINGS_MODULE") == "docappsystem.settings_local"
    and settings.DEBUG is False
    and settings.LOGIN_ACCOUNTING_ENABLED is False
    and settings.DATABASES["default"]["HOST"] == "db"
    and settings.USE_X_FORWARDED_HOST is False
    and settings.USE_X_FORWARDED_PORT is False
    and settings.CSRF_TRUSTED_ORIGINS == []
)
print("SAFE_LOCAL_V3" if safe else "UNSAFE")
' | tr -d '\r\n')" || fail 'Cannot inspect Django local runtime'
[[ "$runtime" == SAFE_LOCAL_V3 ]] || fail 'Refusing unsafe Django runtime'

[[ $(flag) == False ]] || fail 'Existing app must have V3 OFF initially'
[[ $(redis_cli PING) == PONG ]] || fail 'Redis DB0 not ready'
base_flag="$("${base[@]}" run --rm -T --no-deps app python -c \
  'from django.conf import settings; print(settings.LOGIN_ACCOUNTING_ENABLED)' \
  | tail -n1 | tr -d '\r\n')"
[[ "$base_flag" == False ]] || fail 'Base Compose must keep V3 OFF'
pass 'Feature flag OFF in base runtime and rollback configuration'
pass 'Loopback HTTPS, healthy services and safe local runtime verified'

overlay="$(mktemp ./.asg-a34-login-XXXXXX.yml)" || fail 'Cannot create local overlay'
test_compose=(docker compose --env-file .env.local \
  -f docker-compose.dev.yml -f "$overlay")
cat > "$overlay" <<'YAML'
services:
  app:
    environment:
      LOGIN_ACCOUNTING_ENABLED: "true"
YAML
"${test_compose[@]}" config -q || fail 'Invalid local override configuration'
needs_rollback=1
"${test_compose[@]}" up -d --no-deps --force-recreate --wait app
"${test_compose[@]}" up -d --no-deps --force-recreate --wait gateway
[[ $(flag) == True ]] || fail 'V3 was not enabled for local test'
pass 'Isolated local V3 activated'

gateway_id="$("${test_compose[@]}" ps -q gateway)"
network="$(docker inspect "$gateway_id" --format \
  '{{range $n, $_ := .NetworkSettings.Networks}}{{println $n}}{{end}}' | head -n1)"
[[ -n "$network" ]] || fail 'Cannot find gateway network'
docker run --rm -d --name "$client" --network "$network" \
  --entrypoint sh adaptive-security-gateway:local -c 'sleep 600' >/dev/null
client_started=1
ip="$(docker inspect "$client" --format \
  '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
[[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'Invalid client IP'

# Exact HMAC namespace: do not delete existing or unknown Redis keys.
raw_keys="$("${test_compose[@]}" exec -T app python -c \
  'from docappsystem.login_accounting import LoginAccounting; import sys; print("\n".join(LoginAccounting()._keys(sys.argv[1],sys.argv[2],"unused")))' \
  "$ip" "$email")" || fail 'Could not derive HMAC keys'
while IFS= read -r key; do
  [[ -z "$key" || "$key" == bf:v3:req:* ]] && continue
  keys+=("$key")
done <<< "$raw_keys"
[[ ${#keys[@]} -gt 0 ]] || fail 'Expected Redis keys not found'
[[ $(redis_cli EXISTS "${keys[@]}" "blacklist:$ip" "ban:v2:ip:$ip") == 0 ]] || \
  fail 'Synthetic test IP/email namespace already has state'
[[ $(redis_cli SISMEMBER blacklist_ips "$ip") == 0 ]] || \
  fail 'Client IP already manually banned'
owned_keys=1
pass 'Synthetic account and source Redis state absent before test'

# Create one disposable LOCAL test account. Never use a real email/password.
# Track creation *before* invoking Django, even if stdout is lost after COMMIT.
user_create_attempted=1
user_id="$("${test_compose[@]}" exec -T \
  -e "ASG_A34_EMAIL=$email" -e "ASG_A34_NAME=$username" \
  -e "ASG_A34_PASS=$password" \
  app python manage.py shell -c '
import os
from django.contrib.auth import get_user_model
User = get_user_model()
name, mail = os.environ["ASG_A34_NAME"], os.environ["ASG_A34_EMAIL"]
assert not User.objects.filter(username=name).exists()
assert not User.objects.filter(email=mail).exists()
u = User.objects.create_user(
    username=name, email=mail, password=os.environ["ASG_A34_PASS"],
    user_type="1", is_active=True,
)
print(u.pk)
' | tr -d '\r\n')" || fail 'Cannot create isolated local test user'
[[ "$user_id" =~ ^[1-9][0-9]*$ ]] || fail 'Invalid synthetic user ID'
pass 'Isolated valid user created in local Django database'

docker exec "$client" curl -kfsS --max-time 12 \
  -A 'Mozilla/5.0 A34-local-test' -H 'Host: localhost' \
  -c /tmp/a34-cookies -b /tmp/a34-cookies \
  -o /tmp/a34-login.html https://gateway/login/ || \
  fail 'Cannot GET CSRF login form'
csrf="$(docker exec "$client" grep -o \
  'name="csrfmiddlewaretoken" value="[^"]*"' /tmp/a34-login.html \
  | sed -E 's/.*value="([^"]*)".*/\1/' | head -n1)"
[[ -n "$csrf" ]] || fail 'Django CSRF token missing'
pass 'Valid Django CSRF token acquired'

# A forged X-Real-IP from the client must be overwritten by the Gateway.
status="$(docker exec "$client" curl -k -sS --max-time 15 \
  -D /tmp/a34-result.headers -o /dev/null -w '%{http_code}' \
  -A 'Mozilla/5.0 A34-local-test' -H 'Host: localhost' \
  -H 'X-Real-IP: 203.0.113.77' \
  -H 'Origin: https://localhost' --referer https://localhost/login/ \
  -b /tmp/a34-cookies -c /tmp/a34-cookies \
  --data-urlencode "email=$email" \
  --data-urlencode "password=$password" \
  --data-urlencode "csrfmiddlewaretoken=$csrf" \
  https://gateway/doLogin/)" || fail 'Login POST failed at transport layer'
[[ "$status" == 302 ]] || fail "Expected successful login 302, got HTTP $status"
if docker exec "$client" grep -qiE \
  '^X-Login-(Status|Accounting|Alert):' /tmp/a34-result.headers; then
  fail 'Internal accounting headers leaked'
fi
pass 'Correct credentials authenticated without leaking internal headers'

if ! docker exec "$client" grep -q $'\tsessionid\t' /tmp/a34-cookies; then
  fail 'Valid Django session cookie not issued'
fi
profile="$(docker exec "$client" curl -k -sS --max-time 12 \
  -A 'Mozilla/5.0 A34-local-test' -H 'Host: localhost' \
  -b /tmp/a34-cookies -c /tmp/a34-cookies \
  -o /dev/null -w '%{http_code}' https://gateway/profile/)" || \
  fail 'Authenticated profile request failed'
[[ "$profile" == 200 ]] || fail "Authenticated profile expected 200, got $profile"
pass 'Django session created and authenticated profile accessible'

success_key=""
for key in "${keys[@]}"; do
  [[ "$key" == bf:v3:success:* ]] && success_key="$key"
done
[[ -n "$success_key" ]] || fail 'V3 success key missing from derived list'
[[ "$(redis_cli EXISTS "$success_key")" == 1 ]] || \
  fail 'Redis V3 success finalization marker not committed'
[[ "$(redis_cli EXISTS "${keys[0]}" "${keys[1]}")" == 0 ]] || \
  fail 'Successful login incorrectly incremented failed counters'
pass 'Redis V3 success marker exists without failed-login counters'

# Re-acquire CSRF after successful authentication (Django rotates it).
docker exec "$client" curl -kfsS --max-time 12 \
  -A 'Mozilla/5.0 A34-local-test' -H 'Host: localhost' \
  -b /tmp/a34-cookies -c /tmp/a34-cookies \
  -o /tmp/a34-login.html https://gateway/login/ || \
  fail 'Could not refresh CSRF token after login'
csrf_after="$(docker exec "$client" grep -o \
  'name="csrfmiddlewaretoken" value="[^"]*"' /tmp/a34-login.html \
  | sed -E 's/.*value="([^"]*)".*/\1/' | head -n1)"
[[ -n "$csrf_after" ]] || fail 'Refreshed CSRF token missing'

# This failed request must be counted for the real Docker peer IP, not the
# forged X-Real-IP supplied by the client. A successful login alone cannot
# establish this because success does not write a per-IP pair counter.
wrong_status="$(docker exec "$client" curl -k -sS --max-time 15 \
  -o /dev/null -w '%{http_code}' \
  -A 'Mozilla/5.0 A34-local-test' -H 'Host: localhost' \
  -H 'X-Real-IP: 203.0.113.77' \
  -H 'Origin: https://localhost' --referer https://localhost/login/ \
  -b /tmp/a34-cookies -c /tmp/a34-cookies \
  --data-urlencode "email=$email" \
  --data-urlencode 'password=wrong-a34-test-only' \
  --data-urlencode "csrfmiddlewaretoken=$csrf_after" \
  https://gateway/doLogin/)" || fail 'Failed-login source trust probe failed'
[[ "$wrong_status" == 302 ]] || fail 'Failed-login trust probe did not reach Django'
spoof_pair="$("${test_compose[@]}" exec -T app python -c \
  'from docappsystem.login_accounting import LoginAccounting;import sys;print(LoginAccounting()._keys(sys.argv[1],sys.argv[2],"unused")[1])' \
  '203.0.113.77' "$email" | tr -d '\r\n')"
[[ "$(redis_cli GET "${keys[1]}")" == 1 ]] || \
  fail 'Real peer IP did not receive failed-login pair accounting'
[[ "$(redis_cli EXISTS "$spoof_pair")" == 0 ]] || \
  fail 'Forged client X-Real-IP affected accounting'
[[ "$(redis_cli EXISTS "blacklist:$ip" "ban:v2:ip:$ip")" == 0 ]] || \
  fail 'Account guessing unexpectedly caused IP ban'
pass 'Gateway overwrites forged X-Real-IP; failed login binds to real peer IP'
