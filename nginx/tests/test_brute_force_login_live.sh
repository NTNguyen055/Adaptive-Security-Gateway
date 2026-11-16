#!/usr/bin/env bash
# End-to-end Django -> OpenResty -> Redis brute-force integration test.
# Uses a disposable Docker client with its own IP; never uses the host IP.
# Run after the local app/gateway/redis stack is healthy and gateway image is current.
set -Eeuo pipefail
export MSYS_NO_PATHCONV=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

COMPOSE=(docker compose --env-file .env.local -f docker-compose.dev.yml)
CLIENT="asg-bruteforce-live-$$"
CLIENT_STARTED=0
OWN_TEST_KEYS=0
TEST_IP=""
PASSED=0
TEST_AGENT='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
TEST_EMAIL="asg-bruteforce-${$}-$(date +%s)@example.invalid"
TEST_PASSWORD="NotARealPassword-${$}-$(date +%s)"

redis_cli() {
  "${COMPOSE[@]}" exec -T redis redis-cli --raw -n 0 "$@"
}

pass() {
  PASSED=$((PASSED + 1))
  printf 'PASS  %s\n' "$1"
}

fail() {
  printf 'FAIL  %s\n' "$1" >&2
  exit 1
}

cleanup() {
  if [[ "$OWN_TEST_KEYS" -eq 1 && -n "$TEST_IP" ]]; then
    # Delete only keys whose absence was verified before this test began.
    # The manual blacklist_ips SET is deliberately never modified.
    redis_cli del \
      "brute_force:fail:${TEST_IP}" \
      "brute_force:lockout:${TEST_IP}" \
      "brute_force:history:${TEST_IP}" \
      "brute_force:success:${TEST_IP}" \
      "blacklist:${TEST_IP}" \
      "risk:v1:${TEST_IP}" \
      "risk:v1:last_seen:${TEST_IP}" \
      "rrl:${TEST_IP}" \
      "rrl:${TEST_IP}:seq" \
      "rrl:${TEST_IP}:/doLogin/" \
      "rrl:${TEST_IP}:/doLogin/:seq" >/dev/null 2>&1 || true
  fi

  if [[ "$CLIENT_STARTED" -eq 1 ]]; then
    docker rm -f "$CLIENT" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ -f .env.local && -f docker-compose.dev.yml ]] ||
  fail "Local .env.local / docker-compose.dev.yml not found"

[[ "$(redis_cli PING)" == "PONG" ]] || fail "Redis DB0 is not ready"
pass "Redis DB0 responds"

GATEWAY_ID="$("${COMPOSE[@]}" ps -q gateway)"
[[ -n "$GATEWAY_ID" ]] || fail "Local Gateway container is not running"
NETWORK="$(docker inspect "$GATEWAY_ID" --format \
  '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' | head -n 1)"
[[ -n "$NETWORK" ]] || fail "Cannot detect Gateway Docker network"

# Reuse the already-built local Gateway image as a curl-only disposable client.
# No image pull, host networking, host-IP spoofing, or persistent container.
docker run --rm -d \
  --name "$CLIENT" \
  --network "$NETWORK" \
  --entrypoint sh adaptive-security-gateway:local \
  -c 'sleep 900' >/dev/null
CLIENT_STARTED=1

TEST_IP="$(docker inspect "$CLIENT" --format \
  '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
[[ "$TEST_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
  fail "Cannot identify disposable client IP: ${TEST_IP:-empty}"
printf 'Disposable test client: %s (%s)\n' "$CLIENT" "$TEST_IP"

FAIL_KEY="brute_force:fail:${TEST_IP}"
LOCKOUT_KEY="brute_force:lockout:${TEST_IP}"
HISTORY_KEY="brute_force:history:${TEST_IP}"
BLACKLIST_KEY="blacklist:${TEST_IP}"
RISK_KEY="risk:v1:${TEST_IP}"
RISK_STAMP_KEY="risk:v1:last_seen:${TEST_IP}"

# Refuse to overwrite or clean any pre-existing state for this IP.
EXISTING="$(redis_cli EXISTS \
  "$FAIL_KEY" "$LOCKOUT_KEY" "$HISTORY_KEY" \
  "brute_force:success:${TEST_IP}" "$BLACKLIST_KEY" \
  "$RISK_KEY" "$RISK_STAMP_KEY" \
  "rrl:${TEST_IP}" "rrl:${TEST_IP}:seq" \
  "rrl:${TEST_IP}:/doLogin/" "rrl:${TEST_IP}:/doLogin/:seq")"
[[ "$EXISTING" == "0" ]] ||
  fail "Disposable IP already has test-related Redis keys; refusing to overwrite/delete them"
[[ "$(redis_cli SISMEMBER blacklist_ips "$TEST_IP")" == "0" ]] ||
  fail "Disposable IP is already in the persistent manual blacklist"
OWN_TEST_KEYS=1
pass "Disposable IP has no pre-existing brute-force, blacklist, reputation or rate-limit keys"

# GET the real login form first so Django CSRF cookie + masked token are valid.
LOGIN_STATUS="$(docker exec "$CLIENT" curl -k -sS --max-time 10 \
  -c /tmp/asg-bruteforce-cookies -b /tmp/asg-bruteforce-cookies \
  -A "$TEST_AGENT" -H 'Host: localhost' \
  -o /tmp/asg-bruteforce-login.html -w '%{http_code}' \
  https://gateway/login/)" || fail "Cannot GET /login/ through Gateway"
[[ "$LOGIN_STATUS" == "200" ]] ||
  fail "Expected GET /login/ HTTP 200, received $LOGIN_STATUS"
CSRF_TOKEN="$(docker exec "$CLIENT" grep -o \
  'name="csrfmiddlewaretoken" value="[^"]*"' \
  /tmp/asg-bruteforce-login.html | sed -E 's/.*value="([^"]*)".*/\1/' | head -n 1)"
[[ -n "$CSRF_TOKEN" ]] || fail "Could not extract CSRF token from Django login form"
pass "Django login form and CSRF token are available through OpenResty"

post_invalid_login() {
  local status
  status="$(docker exec "$CLIENT" curl -k -sS --max-time 12 \
    -D /tmp/asg-bruteforce-response.headers \
    -o /tmp/asg-bruteforce-response.body \
    -w '%{http_code}' \
    -b /tmp/asg-bruteforce-cookies -c /tmp/asg-bruteforce-cookies \
    -A "$TEST_AGENT" -H 'Host: localhost' \
    -H 'Origin: https://localhost' \
    --referer https://localhost/login/ \
    --data-urlencode "email=${TEST_EMAIL}" \
    --data-urlencode "password=${TEST_PASSWORD}" \
    --data-urlencode "csrfmiddlewaretoken=${CSRF_TOKEN}" \
    https://gateway/doLogin/)" || fail "POST /doLogin/ curl request failed"

  [[ "$status" == "302" ]] ||
    fail "Expected invalid Django login to redirect with HTTP 302, received $status"
  docker exec "$CLIENT" grep -qiE '^X-Login-Status:[[:space:]]*failed' \
    /tmp/asg-bruteforce-response.headers ||
    fail "Django response did not expose X-Login-Status: failed to OpenResty"
}

wait_for_counter() {
  local expected="$1" actual attempt
  for attempt in {1..30}; do
    actual="$(redis_cli GET "$FAIL_KEY")"
    [[ "$actual" == "$expected" ]] && return 0
    sleep 0.2
  done
  fail "Redis failed-attempt counter did not reach ${expected}; last value=${actual:-nil}"
}

wait_for_key() {
  local key="$1" label="$2" attempt
  for attempt in {1..30}; do
    [[ "$(redis_cli EXISTS "$key")" == "1" ]] && {
      pass "$label"
      return 0
    }
    sleep 0.2
  done
  fail "Timed out waiting for Redis key: $key"
}

for attempt in 1 2 3 4 5; do
  post_invalid_login
  pass "Failed login ${attempt}/5 reached Django and returned X-Login-Status: failed"
  wait_for_counter "$attempt"
  pass "Redis failed-attempt counter reached ${attempt}/5"
done

wait_for_key "$LOCKOUT_KEY" "Redis lockout key created on fifth failure"
wait_for_key "$BLACKLIST_KEY" "Automatic blacklist key created on fifth failure"

LOCKOUT_TTL="$(redis_cli TTL "$LOCKOUT_KEY")"
BLACKLIST_TTL="$(redis_cli TTL "$BLACKLIST_KEY")"
[[ "$LOCKOUT_TTL" =~ ^[0-9]+$ ]] && (( LOCKOUT_TTL > 0 && LOCKOUT_TTL <= 3600 )) ||
  fail "Invalid lockout TTL: $LOCKOUT_TTL"
[[ "$BLACKLIST_TTL" =~ ^[0-9]+$ ]] && (( BLACKLIST_TTL > 0 && BLACKLIST_TTL <= 3600 )) ||
  fail "Invalid automatic blacklist TTL: $BLACKLIST_TTL"
pass "Lockout and automatic blacklist have positive bounded TTLs"

RISK_SCORE="$(redis_cli GET "$RISK_KEY")"
python - "$RISK_SCORE" <<'PYTHON' || fail "Risk Engine reputation score is missing or below 80"
import sys
try:
    score = float(sys.argv[1])
except (ValueError, IndexError):
    raise SystemExit(1)
if score < 80:
    raise SystemExit(1)
print(f"PASS  Redis reputation score reached {score:g} (>= 80)")
PYTHON

# Pre-login protection must reject the next request before it reaches Django.
NEXT_STATUS="$(docker exec "$CLIENT" curl -k -sS --max-time 10 \
  -A "$TEST_AGENT" -H 'Host: localhost' \
  -o /dev/null -w '%{http_code}' https://gateway/login/)" ||
  fail "Gateway request after lockout failed at transport level"
[[ "$NEXT_STATUS" == "403" ]] ||
  fail "Expected next GET /login/ to be blocked with HTTP 403, received $NEXT_STATUS"
pass "Next GET /login/ is blocked by Gateway with HTTP 403"

# Also prove the actual login POST is rejected before Django and does not
# increment the already-locked counter again.
BLOCKED_POST_STATUS="$(docker exec "$CLIENT" curl -k -sS --max-time 10 \
  -o /dev/null -w '%{http_code}' \
  -b /tmp/asg-bruteforce-cookies -c /tmp/asg-bruteforce-cookies \
  -A "$TEST_AGENT" -H 'Host: localhost' \
  -H 'Origin: https://localhost' --referer https://localhost/login/ \
  --data-urlencode "email=${TEST_EMAIL}" \
  --data-urlencode "password=${TEST_PASSWORD}" \
  --data-urlencode "csrfmiddlewaretoken=${CSRF_TOKEN}" \
  https://gateway/doLogin/)" ||
  fail "Locked POST /doLogin/ failed at transport level"
[[ "$BLOCKED_POST_STATUS" == "403" ]] ||
  fail "Expected locked POST /doLogin/ HTTP 403, received $BLOCKED_POST_STATUS"
sleep 0.5
[[ "$(redis_cli GET "$FAIL_KEY")" == "5" ]] ||
  fail "Blocked request unexpectedly changed the failed-attempt counter"
pass "Locked POST /doLogin/ is blocked before Django; counter remains exactly 5"

printf '\nBrute-force login live tests: %d passed, 0 failed\n' "$PASSED"
