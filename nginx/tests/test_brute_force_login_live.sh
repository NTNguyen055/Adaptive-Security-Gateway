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
  local email="${1:-$TEST_EMAIL}"
  status="$(docker exec "$CLIENT" curl -k -sS --max-time 12 \
    -D /tmp/asg-bruteforce-response.headers \
    -o /tmp/asg-bruteforce-response.body \
    -w '%{http_code}' \
    -b /tmp/asg-bruteforce-cookies -c /tmp/asg-bruteforce-cookies \
    -A "$TEST_AGENT" -H 'Host: localhost' \
    -H 'Origin: https://localhost' \
    --referer https://localhost/login/ \
    --data-urlencode "email=${email}" \
    --data-urlencode "password=${TEST_PASSWORD}" \
    --data-urlencode "csrfmiddlewaretoken=${CSRF_TOKEN}" \
    https://gateway/doLogin/)" || fail "POST /doLogin/ curl request failed"

  [[ "$status" == "302" ]] ||
    fail "Expected invalid Django login to redirect with HTTP 302, received $status"
  # Internal login headers must never be exposed to clients.
  if docker exec "$CLIENT" grep -qiE \
    '^X-Login-(Status|Accounting|Alert):' \
    /tmp/asg-bruteforce-response.headers; then
    fail "Internal login security header leaked to HTTP client"
  fi
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

# NAT-aware login protection integration.
for attempt in 1 2 3 4 5; do
  post_invalid_login

  pass "Failed login ${attempt}/5 returned HTTP 302"

  wait_for_counter "$attempt"

  pass "Redis telemetry reached ${attempt}/5"
done

assert_no_ip_punishment() {
  local count

  count="$(redis_cli EXISTS \
    "$LOCKOUT_KEY" \
    "$BLACKLIST_KEY" \
    "$RISK_KEY" \
    "$RISK_STAMP_KEY")"

  [[ "$count" == "0" ]] ||
    fail "Login failures created unauthorized IP punishment keys"

  [[ "$(redis_cli SISMEMBER blacklist_ips "$TEST_IP")" == "0" ]] ||
    fail "Manual blacklist was modified unexpectedly"
}

assert_no_ip_punishment
pass "Five login failures created no IP lockout or blacklist"

# Same NAT IP must still be able to visit the login page.
LOGIN_AFTER_FAILURES="$(
  docker exec "$CLIENT" curl -k -sS --max-time 10 \
    -A "$TEST_AGENT" \
    -H 'Host: localhost' \
    -o /dev/null \
    -w '%{http_code}' \
    https://gateway/login/
)" || fail "GET /login/ failed after fifth attempt"

[[ "$LOGIN_AFTER_FAILURES" == "200" ]] ||
  fail "Expected GET /login/ HTTP 200, got $LOGIN_AFTER_FAILURES"

pass "Login page remains available after failure threshold"

# Different account identifier sharing the same disposable IP.
SECOND_EMAIL="asg-second-${$}-$(date +%s)@example.invalid"

post_invalid_login "$SECOND_EMAIL"

wait_for_counter 6
assert_no_ip_punishment

pass "Second account on same NAT IP was not locked out"

printf '\nNAT-aware brute-force live tests: %d passed, 0 failed\n' \
  "$PASSED"
