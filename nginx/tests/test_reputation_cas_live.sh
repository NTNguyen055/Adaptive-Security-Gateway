#!/usr/bin/env bash
# Deterministic concurrency check: 2 requests read the same snapshot, but
# only one may commit. The second must reload and retry against new state.
set -euo pipefail
cd "$(dirname "$0")/../../"
ip="198.51.100.246"
rep="risk:v1:$ip"; stamp="risk:v1:last_seen:$ip"
ban="blacklist:$ip"; bf="brute_force:history:$ip"
container="adaptive-security-local-redis-1"
remote="/tmp/asg_reputation_cas_15.lua"
tmp=$(mktemp); owned=0; passed=0
redis() {
  MSYS_NO_PATHCONV=1 docker compose --env-file .env.local -f docker-compose.dev.yml \
    exec -T redis redis-cli --raw -n 0 "$@"
}
pass() { printf 'PASS  %s\n' "$1"; passed=$((passed+1)); }
check() {
  local got="$1" expect="$2" name="$3"
  if [[ "$got" != "$expect" ]]; then
    echo "FAIL  $name: expected '$expect', got '$got'" >&2; exit 1
  fi
  pass "$name"
}
cleanup() {
  if [[ "$owned" == 1 ]]; then
    redis DEL "$rep" "$stamp" "$ban" "$bf" >/dev/null || true
    MSYS_NO_PATHCONV=1 docker exec "$container" rm -f "$remote" >/dev/null 2>&1 || true
  fi
  rm -f "$tmp"
}
trap cleanup EXIT
[[ $(redis PING) == PONG ]] || { echo 'FAIL  Redis not ready' >&2; exit 1; }
pass 'Redis DB0 responds'
for k in "$rep" "$stamp" "$ban" "$bf"; do
  [[ $(redis EXISTS "$k") == 0 ]] || { echo "STOP  Existing test key $k" >&2; exit 1; }
done
[[ $(redis SISMEMBER blacklist_ips "$ip") == 0 ]] || { echo 'STOP  Existing manual ban' >&2; exit 1; }
pass 'Isolated IP has no existing data'
awk '/^local WRITE_REPUTATION_SCRIPT = \[\[/{f=1;next} f && /^\]\]/{exit} f {print}' \
  nginx/lua/risk_engine.lua > "$tmp"
grep -q 'expected_score' "$tmp" || { echo 'FAIL  Missing CAS script' >&2; exit 1; }
pass 'Extracted exact CAS script from Risk Engine'
owned=1
MSYS_NO_PATHCONV=1 docker exec -i "$container" sh -c \
  'cat > /tmp/asg_reputation_cas_15.lua' < "$tmp"
run_eval() {
  redis --eval "$remote" "$rep" "$stamp" "$ban" "$bf" , "$@"
}
missing='__ASG_MISSING__'
# Both concurrent requests observed an empty score and empty timestamp.
check "$(run_eval 30.00 3600 1000 1 0 900 "$missing" "$missing" "$missing")" \
  1 'First concurrent update committed'
check "$(run_eval 30.00 3600 1000 1 0 900 "$missing" "$missing" "$missing")" \
  0 'Stale update rejected, not overwritten'
check "$(redis GET "$rep")" 30.00 'Score unchanged after stale update'
# The caller now recomputes 30(existing) +30(new) =60 and retries.
check "$(run_eval 60.00 7200 1001 1 0 900 30.00 1000 "$missing")" \
  1 'Retried update committed with fresh snapshot'
check "$(redis GET "$rep")" 60.00 'Two increments preserved in stored score'
check "$(redis GET "$stamp")" 1001 'Retry timestamp updated'
check "$(redis EXISTS "$ban")" 0 'No auto-ban below threshold'
# A change to timestamp alone must invalidate a stale CAS.
check "$(run_eval 70.00 7200 1002 1 0 900 60.00 1000 "$missing")" \
  0 'Stale timestamp rejected'
check "$(redis GET "$rep")" 60.00 'Timestamp conflict did not overwrite score'
# A concurrent update to brute-force history also invalidates stale CAS.
check "$(redis SET "$bf" '1000:5' EX 3600)" OK 'Brute-force history changed externally'
check "$(run_eval 70.00 7200 1002 1 0 900 60.00 1001 "$missing")" \
  0 'Stale brute-force history rejected'
check "$(redis GET "$rep")" 60.00 'History conflict did not overwrite score'
check "$(redis SISMEMBER blacklist_ips "$ip")" 0 'Manual blacklist untouched'
echo "Redis CAS concurrency tests: $passed passed, 0 failed, $passed total"
