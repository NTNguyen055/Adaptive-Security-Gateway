#!/usr/bin/env bash
# Stage 1.5: Redis DB0 live data-model tests, using reserved TEST-NET-2 IP only.
# Run from repository root in Git Bash: bash nginx/tests/test_blacklist_redis_live.sh
set -euo pipefail

compose=(docker compose --env-file .env.local -f docker-compose.dev.yml)
redis_cli() {
  MSYS_NO_PATHCONV=1 "${compose[@]}" exec -T redis redis-cli --raw -n 0 "$@"
}

TEST_IP='198.51.100.243'
AUTO_KEY="blacklist:${TEST_IP}"
REP_KEY="risk:v1:${TEST_IP}"
STAMP_KEY="risk:v1:last_seen:${TEST_IP}"
MANUAL_SET='blacklist_ips'
passed=0

ok() {
  passed=$((passed + 1))
  printf 'PASS  %s\n' "$1"
}
fail() {
  printf 'FAIL  %s\n' "$1" >&2
  exit 1
}
expect_eq() {
  local actual="$1" wanted="$2" title="$3"
  if [[ "$actual" == "$wanted" ]]; then ok "$title"; else
    printf 'Expected <%s>, got <%s>\n' "$wanted" "$actual" >&2
    fail "$title"
  fi
}
cleanup() {
  # Only the reserved test IP is affected. Never FLUSHDB or clear blacklist_ips.
  redis_cli srem "$MANUAL_SET" "$TEST_IP" >/dev/null 2>&1 || true
  redis_cli del "$AUTO_KEY" "$REP_KEY" "$STAMP_KEY" >/dev/null 2>&1 || true
}

printf 'Stage 1.5 Redis integration — isolated test IP %s\n' "$TEST_IP"
expect_eq "$(redis_cli ping)" 'PONG' 'Redis DB0 responds'

if [[ "$(redis_cli exists "$AUTO_KEY" "$REP_KEY" "$STAMP_KEY")" != '0' ]] ||
   [[ "$(redis_cli sismember "$MANUAL_SET" "$TEST_IP")" != '0' ]]; then
  fail 'Reserved test keys already contain data; refusing to overwrite or delete them'
fi
ok 'Reserved test IP has no pre-existing data'
trap cleanup EXIT

expect_eq "$(redis_cli set "$AUTO_KEY" 1 EX 7)" 'OK' 'Temporary automatic ban key created'
expect_eq "$(redis_cli sismember "$MANUAL_SET" "$TEST_IP")" '0' 'Automatic ban did not add persistent manual membership'
ms="$(redis_cli pttl "$AUTO_KEY")"
if [[ "$ms" =~ ^[0-9]+$ ]] && (( ms > 0 && ms <= 7000 )); then
  ok 'Automatic ban has positive bounded TTL'
else
  fail "Invalid auto-ban PTTL: $ms"
fi

sleep 8
expect_eq "$(redis_cli get "$AUTO_KEY")" '' 'Automatic ban expires naturally'

expect_eq "$(redis_cli sadd "$MANUAL_SET" "$TEST_IP")" '1' 'Manual ban membership created'
expect_eq "$(redis_cli sismember "$MANUAL_SET" "$TEST_IP")" '1' 'Manual ban persists without automatic key'
expect_eq "$(redis_cli set "$AUTO_KEY" 1 EX 3)" 'OK' 'Manual and automatic bans can coexist'
sleep 4
expect_eq "$(redis_cli get "$AUTO_KEY")" '' 'Automatic ban expires while manual ban remains'
expect_eq "$(redis_cli sismember "$MANUAL_SET" "$TEST_IP")" '1' 'Manual membership survives automatic TTL'
expect_eq "$(redis_cli srem "$MANUAL_SET" "$TEST_IP")" '1' 'Manual unban removes manual membership'
expect_eq "$(redis_cli sismember "$MANUAL_SET" "$TEST_IP")" '0' 'Manual unban is observable'

expect_eq "$(redis_cli set "$REP_KEY" 65.00 EX 3)" 'OK' 'Reputation score created with expiry'
expect_eq "$(redis_cli set "$STAMP_KEY" 1760000000 EX 3)" 'OK' 'Reputation timestamp created with expiry'
sleep 4
expect_eq "$(redis_cli exists "$REP_KEY" "$STAMP_KEY")" '0' 'Reputation and timestamp expire together'
expect_eq "$(redis_cli exists "$AUTO_KEY" "$REP_KEY" "$STAMP_KEY")" '0' 'No test IP keys remain after natural expiry'
printf 'Redis blacklist live tests: %d passed, 0 failed, %d total\n' "$passed" "$passed"
