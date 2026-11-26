
#!/usr/bin/env bash
# P0.2.4-A3.1: verify the EXACT Risk Engine Redis EVAL is reputation-only.
# Reserved TEST-NET IP. Never FLUSHDB; never modify the manual blacklist set.
set -Eeuo pipefail
cd "$(dirname "$0")/../../"

source_file="nginx/lua/risk_engine.lua"
ip="198.51.100.244"
rep="risk:v1:$ip"
stamp="risk:v1:last_seen:$ip"
ban="blacklist:$ip"
bf="brute_force:history:$ip"
remote_file="/tmp/asg_reputation_a3_${BASHPID:-$$}.lua"
script_file="$(mktemp)"
owned=0
passed=0

compose=(docker compose --env-file .env.local -f docker-compose.dev.yml)

redis() {
  MSYS_NO_PATHCONV=1 "${compose[@]}" exec -T redis redis-cli --raw -n 0 "$@"
}

pass() {
  printf 'PASS  %s\n' "$1"
  passed=$((passed + 1))
}

assert_eq() {
  local got="$1" expected="$2" label="$3"

  if [[ "$got" != "$expected" ]]; then
    printf 'FAIL  %s: expected <%s>, got <%s>\n' \
      "$label" "$expected" "$got" >&2
    exit 1
  fi

  pass "$label"
}

cleanup() {
  if [[ "$owned" == 1 ]]; then
    redis DEL "$rep" "$stamp" "$ban" "$bf" >/dev/null 2>&1 || true

    MSYS_NO_PATHCONV=1 "${compose[@]}" exec -T redis \
      rm -f "$remote_file" >/dev/null 2>&1 || true
  fi

  rm -f "$script_file"
}

trap cleanup EXIT

[[ -f "$source_file" ]] || {
  echo "FAIL  Missing $source_file" >&2
  exit 1
}

assert_eq "$(redis PING)" "PONG" "Redis DB 0 responds"

# Do not overwrite existing Redis state.
for key in "$rep" "$stamp" "$ban" "$bf"; do
  [[ "$(redis EXISTS "$key")" == 0 ]] || {
    printf 'STOP  Test key already exists: %s\n' "$key" >&2
    exit 1
  }
done

[[ "$(redis SISMEMBER blacklist_ips "$ip")" == 0 ]] || {
  echo "STOP  Test IP is in manual blacklist_ips" >&2
  exit 1
}

pass "Reserved test IP has no existing state"

# Extract the production Redis Lua script verbatim.
awk '/^local WRITE_REPUTATION_SCRIPT = \[\[/{f=1;next} f && /^\]\]/{exit} f {print}' \
  "$source_file" > "$script_file"

[[ -s "$script_file" ]] || {
  echo "FAIL  Embedded EVAL script not found" >&2
  exit 1
}

grep -Fq "redis.call('SET', score_key" "$script_file" || {
  echo "FAIL  Extracted script does not write reputation" >&2
  exit 1
}

pass "Extracted Risk Engine reputation EVAL"

# Upload the test script to the Redis container, not the host /tmp.
owned=1

MSYS_NO_PATHCONV=1 "${compose[@]}" exec -T redis sh -c \
  'cat > "$1"' sh "$remote_file" < "$script_file"

# TEST 1: High risk may write reputation, never IP blacklist.
assert_eq "$(redis --eval "$remote_file" "$rep" "$stamp" "$ban" "$bf" , \
  85.00 7200 1234567890 1 0 900 \
  __ASG_MISSING__ __ASG_MISSING__ __ASG_MISSING__)" \
  "1" "High-risk reputation EVAL committed"

assert_eq "$(redis GET "$rep")" \
  "85.00" "Reputation score stored"

assert_eq "$(redis GET "$stamp")" \
  "1234567890" "Last-seen timestamp stored"

assert_eq "$(redis EXISTS "$ban")" \
  "0" "High risk did not issue IP blacklist"

assert_eq "$(redis SISMEMBER blacklist_ips "$ip")" \
  "0" "Manual blacklist untouched"

rep_ttl="$(redis TTL "$rep")"
stamp_ttl="$(redis TTL "$stamp")"

if (( rep_ttl > 0 && rep_ttl <= 7200 &&
      stamp_ttl > 0 && stamp_ttl <= 7200 )); then
  pass "Reputation and timestamp TTL bounded to 7200s"
else
  printf 'FAIL  Invalid TTLs: reputation=%s timestamp=%s\n' \
    "$rep_ttl" "$stamp_ttl" >&2
  exit 1
fi

# TEST 2: An old caller must not be allowed to request write_ban=1.
# The CAS snapshots match, so the rejection tests authorization.
rejected="$(redis --eval "$remote_file" "$rep" "$stamp" "$ban" "$bf" , \
  95.00 7200 1234567891 1 1 900 \
  85.00 1234567890 __ASG_MISSING__ 2>&1 || true)"

if [[ "$rejected" == *"invalid reputation script args"* ]]; then
  pass "Legacy write_ban=1 is rejected by Redis EVAL"
else
  printf 'FAIL  Unauthorized ban write was not rejected: %s\n' \
    "$rejected" >&2
  exit 1
fi

assert_eq "$(redis GET "$rep")" \
  "85.00" "Rejected ban did not mutate reputation"

assert_eq "$(redis GET "$stamp")" \
  "1234567890" "Rejected ban did not mutate timestamp"

assert_eq "$(redis EXISTS "$ban")" \
  "0" "Rejected ban did not create blacklist"

# TEST 3: Low-risk reputation update remains functional.
assert_eq "$(redis DEL "$rep" "$stamp" "$ban" "$bf")" \
  "2" "Reset reputation and timestamp between scenarios"

assert_eq "$(redis --eval "$remote_file" "$rep" "$stamp" "$ban" "$bf" , \
  20.00 3600 0 0 0 900 \
  __ASG_MISSING__ __ASG_MISSING__ __ASG_MISSING__)" \
  "1" "Low-risk EVAL committed"

assert_eq "$(redis GET "$rep")" \
  "20.00" "Low-risk reputation stored"

assert_eq "$(redis EXISTS "$stamp" "$ban")" \
  "0" "Low-risk update did not create timestamp or blacklist"

# TEST 4: Invalid TTL must not leave partial Redis state.
assert_eq "$(redis DEL "$rep")" \
  "1" "Reset low-risk reputation"

rejected="$(redis --eval "$remote_file" "$rep" "$stamp" "$ban" "$bf" , \
  95.00 0 123 1 0 900 \
  __ASG_MISSING__ __ASG_MISSING__ __ASG_MISSING__ 2>&1 || true)"

if [[ "$rejected" == *"invalid reputation script args"* ]]; then
  pass "Invalid reputation TTL rejected"
else
  printf 'FAIL  Invalid TTL was not rejected: %s\n' \
    "$rejected" >&2
  exit 1
fi

assert_eq "$(redis EXISTS "$rep" "$stamp" "$ban" "$bf")" \
  "0" "Rejected EVAL left no test keys"

assert_eq "$(redis SISMEMBER blacklist_ips "$ip")" \
  "0" "Manual blacklist remains untouched"

printf 'Redis A3 reputation-only live tests: %d passed, 0 failed, %d total\n' \
  "$passed" "$passed"
