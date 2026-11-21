#!/usr/bin/env bash
# LOCAL Redis persistence + OpenResty enforcement E2E.
# Uses the exact Redis Lua script embedded in ip_ban_issuer.lua.
# This test directly invokes EVAL with synthetic incident data; it is NOT a
# production-correlator integration test. Production issuance stays disabled
# until a trusted in-process security_correlator is implemented and verified.
# No production use and no FLUSHDB / arbitrary-key cleanup.
set -Eeuo pipefail
export MSYS_NO_PATHCONV=1

cd "$(dirname "$0")/../../"
compose=(docker compose --env-file .env.local -f docker-compose.dev.yml)
client="asg-a34-ban-$$"
client_started=0
owned=0
ip=""
passed=0
temp_script="$(mktemp ./.asg-a34-issuer-XXXXXX.lua)"
redis_path="/tmp/asg-a34-issuer-$$.lua"
redis_id=""

redis_cli() { "${compose[@]}" exec -T redis redis-cli --raw -n 0 "$@" | tr -d '\r'; }
pass() { printf 'PASS  %s\n' "$1"; passed=$((passed + 1)); }
fail() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  if [[ "$owned" -eq 1 && -n "$ip" ]]; then
    redis_cli DEL "ban:v2:ip:$ip" >/dev/null 2>&1
  fi
  if [[ "$client_started" -eq 1 ]]; then
    docker rm -f "$client" >/dev/null 2>&1
  fi
  if [[ -n "$redis_id" ]]; then
    docker exec "$redis_id" rm -f "$redis_path" >/dev/null 2>&1
  fi
  rm -f "$temp_script"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ -f .env.local && -f docker-compose.dev.yml ]] || fail 'Local stack not configured'
[[ "$(redis_cli PING)" == PONG ]] || fail 'Redis DB0 unavailable'
pass 'Local Redis DB0 responds'

redis_id="$("${compose[@]}" ps -q redis)"
gateway_id="$("${compose[@]}" ps -q gateway)"
[[ -n "$redis_id" && -n "$gateway_id" ]] || fail 'Gateway/Redis not running'
network="$(docker inspect "$gateway_id" --format \
  '{{range $n, $_ := .NetworkSettings.Networks}}{{println $n}}{{end}}' | head -n1)"
[[ -n "$network" ]] || fail 'Gateway Docker network not found'

docker run --rm -d --name "$client" --network "$network" \
  --entrypoint sh adaptive-security-gateway:local -c 'sleep 900' >/dev/null
client_started=1
ip="$(docker inspect "$client" --format \
  '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
[[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'Invalid disposable client IP'
key="ban:v2:ip:$ip"
legacy="blacklist:$ip"
[[ "$(redis_cli EXISTS "$key" "$legacy")" == 0 ]] || fail 'Test IP already has ban state'
[[ "$(redis_cli SISMEMBER blacklist_ips "$ip")" == 0 ]] || fail 'Test IP manually banned'
owned=1
pass 'Disposable test IP has no pre-existing ban state'

# Extract exactly the production writer's Redis script; no duplicate logic.
sed -n '/^local ISSUE_SCRIPT = \[\[$/,/^\]\]$/p' \
  nginx/lua/ip_ban_issuer.lua | sed '1d;$d' > "$temp_script"
[[ -s "$temp_script" ]] || fail 'Cannot extract production Redis issuance script'
docker cp "$temp_script" "$redis_id:$redis_path" || fail 'Could not copy EVAL to Redis container'
pass 'Exact Redis issuance EVAL extracted and staged'

redis_eval() {
  docker exec "$redis_id" redis-cli --raw -n 0 \
    --eval "$redis_path" "$key" , "$ip" "$1" "$2" | tr -d '\r'
}

# Preflight must reject invalid TTL without modifying Redis.
incident='abcdeffedcba0123456789abcdef0001'
invalid_result="$(redis_eval "$incident" 301 2>&1 || true)"
[[ "$invalid_result" == *'invalid authorized ban arguments'* ]] || \
  fail 'Invalid TTL was not rejected by Redis script'
[[ "$(redis_cli EXISTS "$key")" == 0 ]] || fail 'Invalid TTL created a ban'
pass 'Out-of-bounds TTL rejected without state change'

http_status() {
  docker exec "$client" curl -k -sS --max-time 10 \
    -H 'Host: localhost' -o /dev/null -w '%{http_code}' \
    'https://gateway/userbase/'
}
[[ "$(http_status)" == 200 ]] || fail 'Clean test IP is not allowed'
pass 'Clean HTTP request passes'

[[ "$(redis_eval "$incident" 12)" == 1 ]] || fail 'Atomic authorized ban SET NX EX failed'
raw="$(redis_cli GET "$key")"
python - "$raw" "$ip" "$incident" <<'PYTHON' || fail 'Ban provenance metadata invalid'
import json
import sys
r = json.loads(sys.argv[1])
assert r['schema'] == 1
assert r['scope'] == 'ip'
assert r['ip'] == sys.argv[2]
assert r['incident_id'] == sys.argv[3]
assert r['issuer'] == 'security_correlator'
assert r['reason'] == 'confirmed_exploit_campaign'
assert r['ttl_seconds'] == 12
assert r['expires_at'] - r['issued_at'] == 12
PYTHON
pass 'Atomic ban contains provenance and bounded TTL'

before="$(redis_cli PTTL "$key")"
[[ "$before" =~ ^[0-9]+$ ]] && (( before > 0 && before <= 12000 )) || \
  fail 'Ban TTL not bounded'
[[ "$(redis_eval 'ffffffffffffffffffffffffffffffff' 12)" == 0 ]] || \
  fail 'Existing ban was overwritten'
after="$(redis_cli PTTL "$key")"
[[ "$after" =~ ^[0-9]+$ ]] && (( after > 0 && after <= before )) || \
  fail 'Duplicate issuance prolonged TTL'
[[ "$(redis_cli GET "$key")" == "$raw" ]] || fail 'Duplicate modified metadata'
pass 'Duplicate issuance is idempotent and cannot prolong TTL'

[[ "$(redis_cli EXISTS "$legacy")" == 0 ]] || fail 'Issuer wrote legacy blacklist key'
[[ "$(redis_cli SISMEMBER blacklist_ips "$ip")" == 0 ]] || \
  fail 'Issuer wrote persistent manual ban'
pass 'Legacy automatic ban and manual SET remain untouched'

# The isolated test bypasses writer's local cache invalidation. Respect the
# intentionally bounded 5-second negative-cache visibility window.
sleep 6
[[ "$(http_status)" == 403 ]] || fail 'Authorized ban not enforced as HTTP 403'
pass 'OpenResty enforces authorized TTL ban'

sleep 7
[[ "$(redis_cli EXISTS "$key")" == 0 ]] || fail 'Authorized ban did not expire'
[[ "$(http_status)" == 200 ]] || fail 'Access not restored after ban TTL'
pass 'Authorized ban expires and access is restored'

printf '\nA3.4 authorized ban storage/HTTP E2E: %d passed, 0 failed\n' "$passed"
