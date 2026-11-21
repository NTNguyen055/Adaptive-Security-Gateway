#!/usr/bin/env bash
# local-only Account-Aware Login Accounting HTTP E2E.
# Rebuilds app/gateway, temporarily enables V3, and restores flag OFF on EXIT.
# No users are created; synthetic .invalid identifiers only.
# Never FLUSHDB / DEL by prefix. No production use.
set -Eeuo pipefail
export MSYS_NO_PATHCONV=1

cd "$(dirname "$0")/../../"
BASE=(docker compose --env-file .env.local -f docker-compose.dev.yml)
OVERLAY="$(mktemp ./.asg-a33-compose-XXXXXX.yml)"
TEST=(docker compose --env-file .env.local -f docker-compose.dev.yml -f "$OVERLAY")
CLIENTS=()
KEYS=()
OWNED=0
NEED_ROLLBACK=0
PASS=0

redis() { "${BASE[@]}" exec -T redis redis-cli --raw -n 0 "$@" | tr -d '\r'; }
pass() { printf 'PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }
flag() {
  "${BASE[@]}" exec -T app python -c \
    'from django.conf import settings; print(settings.LOGIN_ACCOUNTING_ENABLED)' \
    | tr -d '\r\n'
}
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  for client in "${CLIENTS[@]}"; do
    docker rm -f "$client" >/dev/null 2>&1
  done
  if (( OWNED == 1 && ${#KEYS[@]} > 0 )); then
    redis DEL "${KEYS[@]}" >/dev/null 2>&1
  fi
  if (( NEED_ROLLBACK == 1 )); then
    echo '=== Restoring LOGIN_ACCOUNTING_ENABLED=false ==='
    "${BASE[@]}" up -d --no-deps --force-recreate --wait app || rc=1
    "${BASE[@]}" up -d --no-deps --force-recreate --wait gateway || rc=1
    if [[ $(flag) != 'False' ]]; then
      echo 'CRITICAL: Accounting flag not restored OFF' >&2
      rc=1
    fi
  fi
  rm -f "$OVERLAY"
  if (( rc == 0 )); then
    printf 'A3.3 local account-aware HTTP E2E: %d passed, 0 failed\n' "$PASS"
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ -f .env.local && -f docker-compose.dev.yml ]] || fail 'Missing local compose/env'
[[ $(redis PING) == PONG ]] || fail 'Redis unavailable'
[[ $(flag) == False ]] || fail 'Running Django flag must be OFF initially'
base_flag="$("${BASE[@]}" run --rm -T --no-deps app python -c \
  'from django.conf import settings; print(settings.LOGIN_ACCOUNTING_ENABLED)' \
  | tail -n1 | tr -d '\r\n')"
[[ "$base_flag" == False ]] || fail 'Base Docker Compose must have flag OFF for rollback'
pass 'Initial app and base Compose both have accounting disabled'

cat > "$OVERLAY" <<'YAML'
services:
  app:
    environment:
      LOGIN_ACCOUNTING_ENABLED: "true"
YAML

# Validate the temporary Compose overlay before changing runtime.
[[ -f "$OVERLAY" ]] || fail "Temporary Compose overlay was not created"

"${TEST[@]}" config -q ||
  fail "Temporary Compose overlay is invalid"

# Do not switch to a potentially stale image when testing migration.
"${BASE[@]}" build app gateway
NEED_ROLLBACK=1
"${TEST[@]}" up -d --no-deps --force-recreate --wait app
"${TEST[@]}" up -d --no-deps --force-recreate --wait gateway
[[ $(flag) == True ]] || fail 'Runtime accounting flag was not enabled'
pass 'Account-aware V3 enabled only for isolated local test'

GATEWAY_ID="$("${TEST[@]}" ps -q gateway)"
NETWORK="$(docker inspect "$GATEWAY_ID" --format \
  '{{range $n, $_ := .NetworkSettings.Networks}}{{println $n}}{{end}}' | head -n1)"
[[ -n "$NETWORK" ]] || fail 'Cannot find disposable Docker network'

new_client() {
  local name="asg-a33-$(date +%s)-$RANDOM"
  docker run -d --name "$name" --network "$NETWORK" \
    --entrypoint sh adaptive-security-gateway:local \
    -c 'sleep 900' >/dev/null
  CLIENTS+=("$name")
  printf '%s' "$name"
}

# Do not invoke new_client inside command substitution: changes to CLIENTS
# would execute in a subshell and escape cleanup tracking.
new_client >/dev/null
CLIENT1="${CLIENTS[0]}"
new_client >/dev/null
CLIENT2="${CLIENTS[1]}"
IP1="$(docker inspect "$CLIENT1" --format \
  '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
IP2="$(docker inspect "$CLIENT2" --format \
  '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
[[ "$IP1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && \
   "$IP2" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && \
   "$IP1" != "$IP2" ]] || fail 'Invalid disposable client IPs'

SUFFIX="$(date +%s)-$RANDOM"
EMAIL_A="a33-a-${SUFFIX}@example.invalid"
EMAIL_B="a33-b-${SUFFIX}@example.invalid"

# Derive the exact HMAC Redis keys using the same Django code. Never calculate
# keys from raw email or delete arbitrary Redis namespace prefixes.
append_keys() {
  local ip="$1" email="$2" raw
  raw="$("${TEST[@]}" exec -T app python -c \
    'from docappsystem.login_accounting import LoginAccounting; import sys; print("\n".join(LoginAccounting()._keys(sys.argv[1], sys.argv[2], "unused")))' \
    "$ip" "$email")" || fail 'Unable to derive isolated V3 keys'
  while IFS= read -r key; do
    [[ "$key" == bf:v3:req:* || -z "$key" ]] && continue
    KEYS+=("$key")
  done <<< "$raw"
}
append_keys "$IP1" "$EMAIL_A"
append_keys "$IP1" "$EMAIL_B"
append_keys "$IP2" "$EMAIL_A"
KEYS+=("brute_force:fail:$IP1" "brute_force:fail:$IP2")
KEYS+=("brute_force:lockout:$IP1" "brute_force:lockout:$IP2")
KEYS+=("blacklist:$IP1" "blacklist:$IP2")
KEYS+=("risk:v1:$IP1" "risk:v1:$IP2")
mapfile -t KEYS < <(printf '%s\n' "${KEYS[@]}" | sort -u)

[[ $(redis EXISTS "${KEYS[@]}") == 0 ]] ||
  fail 'Isolated client already owns keys: refusing to overwrite/delete'
[[ $(redis SISMEMBER blacklist_ips "$IP1") == 0 && \
   $(redis SISMEMBER blacklist_ips "$IP2") == 0 ]] ||
  fail 'Disposable client belongs to manual blacklist'
OWNED=1
pass 'Exact synthetic Redis keys were absent before test'

login_form() {
  local client="$1"
  docker exec "$client" curl -kfsS --max-time 12 \
    -A 'Mozilla/5.0 A33-local-test' -H 'Host: localhost' \
    -c /tmp/a33-cookies -b /tmp/a33-cookies \
    -o /tmp/a33-login.html https://gateway/login/ ||
      fail 'Cannot GET Django login form'
  local token
  token="$(docker exec "$client" grep -o \
    'name="csrfmiddlewaretoken" value="[^"]*"' /tmp/a33-login.html \
    | sed -E 's/.*value="([^"]*)".*/\1/' | head -n1)"
  [[ -n "$token" ]] || fail 'CSRF token missing'
  printf '%s' "$token"
}
CSRF1="$(login_form "$CLIENT1")"
CSRF2="$(login_form "$CLIENT2")"
pass 'Both clients received valid CSRF forms'

post_wrong() {
  local client="$1" csrf="$2" email="$3" expected="$4" actual
  actual="$(docker exec "$client" curl -k -sS --max-time 15 \
    -D /tmp/a33-response.headers -o /dev/null -w '%{http_code}' \
    -b /tmp/a33-cookies -c /tmp/a33-cookies \
    -A 'Mozilla/5.0 A33-local-test' -H 'Host: localhost' \
    -H 'Origin: https://localhost' --referer https://localhost/login/ \
    --data-urlencode "email=$email" \
    --data-urlencode 'password=wrong-a33-synthetic' \
    --data-urlencode "csrfmiddlewaretoken=$csrf" \
    https://gateway/doLogin/)" || fail 'POST failed at transport level'
  [[ "$actual" == "$expected" ]] ||
    fail "Unexpected POST code for client $client: expected $expected got $actual"
  if docker exec "$client" grep -qiE \
    '^X-Login-(Status|Accounting|Alert):' /tmp/a33-response.headers; then
    fail 'Internal accounting headers leaked to client'
  fi
}

for i in 1 2 3 4 5 6; do
  post_wrong "$CLIENT1" "$CSRF1" "$EMAIL_A" 302
done
post_wrong "$CLIENT1" "$CSRF1" "$EMAIL_A" 429
pass 'Repeated guesses on one account/source enter bounded backoff, not IP ban'

GET_AFTER_BACKOFF="$(docker exec "$CLIENT1" curl -k -sS --max-time 10 \
  -A 'Mozilla/5.0 A33-local-test' -H 'Host: localhost' \
  -o /dev/null -w '%{http_code}' https://gateway/login/)"
[[ "$GET_AFTER_BACKOFF" == 200 ]] || fail 'Account backoff blocked the shared login page'
pass 'Account backoff does not close the shared NAT login page'

post_wrong "$CLIENT1" "$CSRF1" "$EMAIL_B" 302
pass 'Different account identifier on same NAT IP reaches Django independently'

post_wrong "$CLIENT2" "$CSRF2" "$EMAIL_A" 302
pass 'Same account across a second IP contributes to shared account telemetry'

ACCT_KEY="$("${TEST[@]}" exec -T app python -c \
  'from docappsystem.login_accounting import LoginAccounting;import sys;print(LoginAccounting()._keys(sys.argv[1],sys.argv[2],"unused")[0])' \
  "$IP1" "$EMAIL_A" | tr -d '\r\n')"
PAIR1="$("${TEST[@]}" exec -T app python -c \
  'from docappsystem.login_accounting import LoginAccounting;import sys;print(LoginAccounting()._keys(sys.argv[1],sys.argv[2],"unused")[1])' \
  "$IP1" "$EMAIL_A" | tr -d '\r\n')"
PAIR2="$("${TEST[@]}" exec -T app python -c \
  'from docappsystem.login_accounting import LoginAccounting;import sys;print(LoginAccounting()._keys(sys.argv[1],sys.argv[2],"unused")[1])' \
  "$IP2" "$EMAIL_A" | tr -d '\r\n')"
[[ $(redis GET "$ACCT_KEY") == 7 ]] || fail 'Global account failure count != 7'
[[ $(redis GET "$PAIR1") == 6 ]] || fail 'First source pair count != 6'
[[ $(redis GET "$PAIR2") == 1 ]] || fail 'Second source pair count != 1'
pass 'One account is correlated across two IPs with distinct pair counters'

for ip in "$IP1" "$IP2"; do
  [[ $(redis EXISTS "blacklist:$ip" "brute_force:lockout:$ip" \
     "risk:v1:$ip" "brute_force:fail:$ip") == 0 ]] ||
    fail 'Legacy IP punishment or duplicate legacy timer was triggered'
done
pass 'V3 writes no IP ban, reputation, lockout or legacy failed-login counter'

[[ $(redis SISMEMBER blacklist_ips "$IP1") == 0 && \
   $(redis SISMEMBER blacklist_ips "$IP2") == 0 ]] ||
  fail 'Manual ban set was modified'
pass 'Manual blacklist remained untouched'
