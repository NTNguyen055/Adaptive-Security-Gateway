#!/usr/bin/env bash
# Stage 1.5: check the EXACT embedded Risk Engine EVAL against local Redis.
# Uses only reserved 198.51.100.244 (RFC 5737 test-net). Never flushes Redis.
set -euo pipefail

cd "$(dirname "$0")/../../"
source_file="nginx/lua/risk_engine.lua"
ip="198.51.100.244"
rep="risk:v1:$ip"
stamp="risk:v1:last_seen:$ip"
ban="blacklist:$ip"
bf="brute_force:history:$ip"
container="adaptive-security-local-redis-1"
remotefile="/tmp/test_reputation_atomic_15.lua"
script_file=$(mktemp)
created=0
passed=0

redis() {
  MSYS_NO_PATHCONV=1 docker compose --env-file .env.local -f docker-compose.dev.yml \
    exec -T redis redis-cli --raw -n 0 "$@"
}
pass() { echo "PASS  $*"; passed=$((passed + 1)); }
assert_eq() {
  local got="$1" wanted="$2" title="$3"
  if [[ "$got" != "$wanted" ]]; then
    echo "FAIL  $title: expected '$wanted', got '$got'" >&2
    exit 1
  fi
  pass "$title"
}
cleanup() {
  if [[ "$created" == 1 ]]; then
    redis DEL "$rep" "$stamp" "$ban" "$bf" >/dev/null || true
    MSYS_NO_PATHCONV=1 docker exec "$container" rm -f "$remotefile" >/dev/null 2>&1 || true
  fi
  rm -f "$script_file"
}
trap cleanup EXIT

if [[ ! -f "$source_file" ]]; then
  echo "FAIL  Missing $source_file" >&2; exit 1
fi
if [[ $(redis PING) != PONG ]]; then
  echo "FAIL  Redis unavailable" >&2; exit 1
fi
pass "Redis DB0 responds"

# Refuse to overwrite any existing test keys or manual membership.
for k in "$rep" "$stamp" "$ban" "$bf"; do
  [[ $(redis EXISTS "$k") == 0 ]] || { echo "STOP  Existing key: $k" >&2; exit 1; }
done
[[ $(redis SISMEMBER blacklist_ips "$ip") == 0 ]] || {
  echo "STOP  Test IP already in blacklist_ips" >&2; exit 1;
}
pass "Reserved test IP has no existing data"

awk '/^local WRITE_REPUTATION_SCRIPT = \[\[/{f=1;next} f && /^\]\]/{exit} f {print}' \
    "$source_file" > "$script_file"
if ! grep -q "redis.call('SET'" "$script_file"; then
  echo "FAIL  Cannot extract embedded write script" >&2; exit 1
fi
pass "Extracted the same Lua script used by Risk Engine"

# In Git Bash, docker cp with MSYS_NO_PATHCONV=1 treats the host's /tmp
# as D:\tmp. Stream source through stdin instead; container /tmp stays Linux.
created=1
MSYS_NO_PATHCONV=1 docker exec -i "$container" sh -c \
  'cat > /tmp/test_reputation_atomic_15.lua' < "$script_file"

# Redis EVAL uses all 3 keys; all 3 are written in one Lua execution.
assert_eq "$(redis --eval "$remotefile" "$rep" "$stamp" "$ban" "$bf" , 85.00 7200 1234567890 1 1 900 __ASG_MISSING__ __ASG_MISSING__ __ASG_MISSING__)" \
  "1" "Atomic EVAL returned success"
assert_eq "$(redis GET "$rep")" "85.00" "Reputation score written"
assert_eq "$(redis GET "$stamp")" "1234567890" "Timestamp written"
assert_eq "$(redis GET "$ban")" "1" "Automatic ban written"
assert_eq "$(redis SISMEMBER blacklist_ips "$ip")" "0" "Manual set not modified"

rttl=$(redis TTL "$rep")
sttl=$(redis TTL "$stamp")
bttl=$(redis TTL "$ban")
if (( rttl > 0 && rttl <= 7200 && sttl > 0 && sttl <= 7200 )); then
  pass "Reputation and timestamp have bounded TTLs"
else
  echo "FAIL  Invalid reputation TTLs: $rttl / $sttl" >&2; exit 1
fi
if (( bttl > 0 && bttl <= 900 )); then
  pass "Automatic ban has <=900s TTL"
else
  echo "FAIL  Invalid automatic ban TTL: $bttl" >&2; exit 1
fi

# A low-risk update after explicit deletion must not create an auto-ban or timestamp.
assert_eq "$(redis DEL "$rep" "$stamp" "$ban" "$bf")" "3" "Test data reset between cases"
assert_eq "$(redis --eval "$remotefile" "$rep" "$stamp" "$ban" "$bf" , 20.00 3600 0 0 0 900 __ASG_MISSING__ __ASG_MISSING__ __ASG_MISSING__)" \
  "1" "Score-only EVAL returned success"
assert_eq "$(redis GET "$rep")" "20.00" "Low reputation written"
assert_eq "$(redis EXISTS "$stamp" "$ban")" "0" "Low risk creates no timestamp/ban when flags off"

# Invalid args should be rejected before any writes (no partial key state).
assert_eq "$(redis DEL "$rep")" "1" "Prepare invalid-argument case"
result=$(redis --eval "$remotefile" "$rep" "$stamp" "$ban" "$bf" , 95.00 0 123 1 1 900 __ASG_MISSING__ __ASG_MISSING__ __ASG_MISSING__ 2>&1 || true)
if [[ "$result" == *"invalid reputation script args"* ]]; then
  pass "Invalid TTL rejected before any Redis write"
else
  echo "FAIL  Expected argument validation error, got: $result" >&2; exit 1
fi
assert_eq "$(redis EXISTS "$rep" "$stamp" "$ban")" "0" "Rejected EVAL left no test keys"

echo "Redis atomic reputation live tests: $passed passed, 0 failed, $passed total"
