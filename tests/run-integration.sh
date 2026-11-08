#!/usr/bin/env bash
# Local integration runner for the existing Redis/HTTP/monitoring tests.
# Run from any directory: bash tests/run-integration.sh [redis|http|monitoring|core|all]
# Strictly local development only. Never runs docker compose down or deletes real volumes.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE="${1:-core}"
COMPOSE=(docker compose --env-file .env.local -f docker-compose.dev.yml)

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

case "$MODE" in
  redis|http|monitoring|core|all) ;;
  *) echo "Usage: bash tests/run-integration.sh [redis|http|monitoring|core|all]"; exit 2 ;;
esac

[[ -f .env.local && -f docker-compose.dev.yml ]] ||
  fail "Local .env.local / docker-compose.dev.yml not found"

command -v docker >/dev/null || fail "Docker CLI is missing"
command -v python >/dev/null || fail "Python is required for local-only configuration guard and JSON tests"
"${COMPOSE[@]}" config --quiet || fail "Invalid local Docker Compose configuration"

# Verify the selected Compose project and the Gateway published ports. Fail
# closed rather than accidentally running these tests against production.
"${COMPOSE[@]}" config --format json | python -c '
import json,sys
cfg=json.load(sys.stdin)
assert cfg.get("name") == "adaptive-security-local", "Not the local Compose project"
gw=cfg["services"]["gateway"]
ports=gw.get("ports",[])
assert ports, "Gateway has no local ports"
assert all(p.get("host_ip") in ("127.0.0.1","::1")
           for p in ports), "Gateway is exposed beyond loopback"
print("PASS: local-only Docker Compose safety guard")
' || fail "Refusing to test a non-local Compose stack"

run_one() {
  local name="$1"
  local path="$2"
  [[ -f "$path" ]] || fail "Missing integration script: $path"
  printf '\n=== %s ===\n' "$name"
  bash "$path"
}

needs_redis=false
needs_gateway=false
needs_monitoring=false
case "$MODE" in
  redis) needs_redis=true ;;
  http) needs_redis=true; needs_gateway=true ;;
  monitoring) needs_gateway=true; needs_monitoring=true ;;
  core) needs_redis=true; needs_gateway=true ;;
  all) needs_redis=true; needs_gateway=true; needs_monitoring=true ;;
esac

if [[ "$needs_redis" == true ]]; then
  [[ -n "$("${COMPOSE[@]}" ps -q redis)" ]] || fail "Local Redis container is not running"
  [[ "$(MSYS_NO_PATHCONV=1 "${COMPOSE[@]}" exec -T redis redis-cli --raw PING)" == "PONG" ]] ||
    fail "Local Redis not ready"
fi
if [[ "$needs_gateway" == true ]]; then
  [[ -n "$("${COMPOSE[@]}" ps -q gateway)" ]] || fail "Local Gateway is not running"
  curl -ksS --max-time 8 --fail https://localhost/userbase/ -o /dev/null ||
    fail "Local Gateway is not reachable through HTTPS"
fi
if [[ "$needs_monitoring" == true ]]; then
  [[ -n "$("${COMPOSE[@]}" --profile monitoring ps -q prometheus)" ]] ||
    fail "Prometheus not started (start the monitoring profile)"
  [[ -n "$("${COMPOSE[@]}" --profile monitoring ps -q grafana)" ]] ||
    fail "Grafana not started (start the monitoring profile)"
fi

count=0
if [[ "$MODE" == redis || "$MODE" == core || "$MODE" == all ]]; then
  run_one "Blacklist Redis data model" nginx/tests/test_blacklist_redis_live.sh
  ((count+=1))
  run_one "Atomic reputation EVAL" nginx/tests/test_reputation_atomic_live.sh
  ((count+=1))
  run_one "CAS concurrency conflict" nginx/tests/test_reputation_cas_live.sh
  ((count+=1))
  run_one "Isolated Redis crash / AOF recovery" tests/helpers/redis-recovery.sh
  ((count+=1))
fi

if [[ "$MODE" == http || "$MODE" == core || "$MODE" == all ]]; then
  run_one "HTTP blacklist lifecycle" nginx/tests/test_blacklist_http_live.sh
  ((count+=1))
  run_one "Structured security JSON access logs" nginx/tests/test_security_json_live.sh
  ((count+=1))
fi

if [[ "$MODE" == monitoring || "$MODE" == all ]]; then
  run_one "Prometheus / Grafana integration" nginx/tests/test_monitoring_live.sh
  ((count+=1))
fi

printf '\nINTEGRATION RUNNER: PASS (%d suites, mode=%s)\n' "$count" "$MODE"
