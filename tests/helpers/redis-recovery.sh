#!/usr/bin/env bash
# Isolated integration: verify AOF persistence after abrupt Redis process termination.
# Creates an isolated container + dedicated disposable volume; NO host ports,
# NO Docker network, NO access to local Gateway/real Redis data or volumes.
set -Eeuo pipefail
export MSYS_NO_PATHCONV=1

container="asg-test-aof-$$_${RANDOM}"
volume="asg_test_aof_$$_${RANDOM}"
volume_owned=0
container_owned=0
passed=0
test_ip="198.51.100.248"

pass() { printf 'PASS: %s\n' "$1"; passed=$((passed+1)); }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [[ "$container_owned" -eq 1 ]]; then
    docker rm -f "$container" >/dev/null 2>&1 || true
  fi
  if [[ "$volume_owned" -eq 1 ]]; then
    if ! docker volume rm "$volume" >/dev/null 2>&1; then
      printf 'WARN: could not remove disposable test volume: %s\n' "$volume" >&2
    fi
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Prevent collisions and avoid touching anything not created by this script.
if docker container inspect "$container" >/dev/null 2>&1; then
  fail "Test container already exists: $container"
fi
if docker volume inspect "$volume" >/dev/null 2>&1; then
  fail "Test volume already exists: $volume"
fi
docker image inspect redis:7-alpine >/dev/null 2>&1 ||
  fail "redis:7-alpine image missing (expected from local Compose setup)"

docker volume create "$volume" >/dev/null
volume_owned=1

start_redis() {
  docker run -d --name "$container" --network none \
    --mount "type=volume,source=${volume},target=/data" \
    redis:7-alpine redis-server \
    --appendonly yes --appendfsync always --save "" \
    --maxmemory 32mb --maxmemory-policy noeviction >/dev/null
  container_owned=1
  local i
  for i in {1..20}; do
    if [[ "$(docker exec "$container" redis-cli --raw PING 2>/dev/null || true)" == PONG ]]; then
      return 0
    fi
    sleep 1
  done
  fail "Isolated Redis did not become ready"
}
redis() { docker exec "$container" redis-cli --raw "$@"; }
check() {
  local got="$1" expected="$2" label="$3"
  [[ "$got" == "$expected" ]] || fail "$label: got '$got' expected '$expected'"
  pass "$label"
}

start_redis
check "$(redis PING)" PONG "isolated Redis running"
check "$(redis CONFIG GET appendonly | tail -n 1)" yes "AOF enabled"
check "$(redis CONFIG GET maxmemory-policy | tail -n 1)" noeviction "noeviction configured"
check "$(redis SADD blacklist_ips "$test_ip")" 1 "synthetic manual ban stored"
check "$(redis SET "blacklist:$test_ip" 1 EX 120)" OK "temporary auto ban stored"
check "$(redis SET "risk:v1:$test_ip" 42.00 EX 120)" OK "synthetic reputation stored"

# Stop the container without graceful shutdown; restart from the same isolated
# named volume. AOF appendfsync=always makes acknowledged writes durable.
docker kill "$container" >/dev/null
docker rm "$container" >/dev/null
container_owned=0
start_redis
check "$(redis PING)" PONG "Redis restarted after SIGKILL"
check "$(redis SISMEMBER blacklist_ips "$test_ip")" 1 "manual ban recovered from AOF"
check "$(redis GET "blacklist:$test_ip")" 1 "temporary auto ban recovered from AOF"
check "$(redis GET "risk:v1:$test_ip")" 42.00 "reputation recovered from AOF"
ttl="$(redis TTL "blacklist:$test_ip")"
if [[ "$ttl" =~ ^[0-9]+$ ]] && (( ttl > 0 && ttl <= 120 )); then
  pass "recovered auto-ban TTL is bounded"
else
  fail "bad recovered TTL: $ttl"
fi
check "$(redis SREM blacklist_ips "$test_ip")" 1 "manual ban can be removed after recovery"
check "$(redis SISMEMBER blacklist_ips "$test_ip")" 0 "manual unban observable"

printf 'Isolated Redis AOF recovery: %d passed, 0 failed, %d total\n' \
  "$passed" "$passed"
