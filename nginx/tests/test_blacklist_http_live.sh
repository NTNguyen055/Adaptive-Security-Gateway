#!/usr/bin/env bash
# Stage 1.5: HTTP integration test using a disposable client with an isolated Docker IP.
# Must run AFTER rebuilding and recreating the gateway with Stage 1.5 code.
# Does not touch your host IP, does not FLUSHDB and doesn't delete existing Redis keys.
set -Eeuo pipefail
# Prevent Git Bash/MSYS from rewriting Docker/container paths and URLs.
export MSYS_NO_PATHCONV=1

cd "$(dirname "$0")/../../"
client="asg-blacklist-http-$$"
client_started=0
manual_created=0
auto_created=0
passed=0
ip=""

compose() { docker compose --env-file .env.local -f docker-compose.dev.yml "$@"; }
redis() { compose exec -T redis redis-cli --raw -n 0 "$@"; }
pass() { printf 'PASS  %s\n' "$1"; passed=$((passed+1)); }
fail() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }
cleanup() {
  if [[ -n "$ip" ]]; then
    if [[ "$manual_created" -eq 1 ]]; then redis SREM blacklist_ips "$ip" >/dev/null || true; fi
    if [[ "$auto_created" -eq 1 ]]; then redis DEL "blacklist:$ip" >/dev/null || true; fi
  fi
  if [[ "$client_started" -eq 1 ]]; then docker rm -f "$client" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ "$(redis PING)" == PONG ]] || fail "Redis is not ready"
pass "Redis responds"
gateway_id="$(compose ps -q gateway)"
[[ -n "$gateway_id" ]] || fail "Gateway container not found"
network="$(docker inspect "$gateway_id" --format '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' | head -n 1)"
[[ -n "$network" ]] || fail "Cannot detect gateway Docker network"

# Reuse existing locally built image as a disposable curl client. No image pull.
docker run --rm -d \
  --name "$client" \
  --network "$network" \
  --entrypoint sh adaptive-security-gateway:local \
  -c 'sleep 180' >/dev/null
client_started=1
ip="$(docker inspect "$client" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
[[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "Cannot identify test client IP: $ip"
echo "Isolated test client: $client ($ip)"

# Never overwrite or remove pre-existing IP ban state.
[[ "$(redis SISMEMBER blacklist_ips "$ip")" == 0 ]] || fail "IP already manually banned: $ip"
[[ "$(redis EXISTS "blacklist:$ip")" == 0 ]] || fail "IP already has an automatic ban key: $ip"
pass "Test client has no existing blacklist state"

http_status() {
  docker exec "$client" curl -k -sS --max-time 8 -o /dev/null -w '%{http_code}' \
    -H 'Host: localhost' 'https://gateway/userbase/'
}
expect_http() {
  local expected="$1" title="$2" got
  got="$(http_status)" || fail "$title: curl failed"
  [[ "$got" == "$expected" ]] || fail "$title: expected HTTP $expected but got $got"
  pass "$title: HTTP $got"
}
expect_http 200 'Clean request'

[[ "$(redis SADD blacklist_ips "$ip")" == 1 ]] || fail 'Cannot insert temporary manual ban'
manual_created=1
pass 'Manual ban inserted into Redis SET'
# The new blacklist module's negative cache is bounded to 5 seconds.
sleep 6
expect_http 403 'Manual ban enforced after negative-cache TTL'
expect_http 403 'Manual ban remains effective'

[[ "$(redis SREM blacklist_ips "$ip")" == 1 ]] || fail 'Cannot remove temporary manual ban'
manual_created=0
pass 'Manual unban accepted'
expect_http 200 'Manual unban immediately reflected by positive-cache revalidation'

# Give previous negative cache 5 seconds to expire while temporary auto ban stays active.
[[ "$(redis SET "blacklist:$ip" 1 EX 10)" == OK ]] || fail 'Cannot set temporary auto ban'
auto_created=1
pass 'Temporary automatic ban created with 10-second TTL'
sleep 6
expect_http 403 'Automatic ban enforced'
sleep 5
[[ "$(redis EXISTS "blacklist:$ip")" == 0 ]] || fail 'Auto ban did not expire'
auto_created=0
pass 'Automatic ban expired in Redis'
expect_http 200 'Access restored after auto-ban expiration'
[[ "$(redis SISMEMBER blacklist_ips "$ip")" == 0 ]] || fail 'Manual SET was unexpectedly modified'
pass 'Manual blacklist SET remains untouched'

printf 'HTTP blacklist live tests: %d passed, 0 failed, %d total\n' "$passed" "$passed"
