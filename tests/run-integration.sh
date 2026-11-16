#!/usr/bin/env bash
# Local integration runner for the existing Redis/HTTP/monitoring tests.
# Run from any directory: bash tests/run-integration.sh [redis|http|monitoring|core|all]
# Strictly local development only. Never starts/stops Compose or deletes volumes.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE="${1:-core}"
COMPOSE=(docker compose --env-file .env.local -f docker-compose.dev.yml)
diagnostics_enabled=0

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

on_exit() {
  local status=$?
  if (( status != 0 )) && [[ "$diagnostics_enabled" == "1" ]]; then
    printf '\n=== Integration failure diagnostics ===\n' >&2
    "${COMPOSE[@]}" ps -a >&2 || true
    for service in redis app gateway; do
      local id health
      id="$("${COMPOSE[@]}" ps -q "$service" 2>/dev/null || true)"
      if [[ -n "$id" ]]; then
        health="$(docker inspect --format \
          '{{.State.Status}}{{if .State.Health}} / health={{.State.Health.Status}}{{end}}' \
          "$id" 2>/dev/null || true)"
        printf '  %s: %s\n' "$service" "${health:-status unavailable}" >&2
      fi
    done
    printf '\n--- Recent local service logs (last 30 lines) ---\n' >&2
    "${COMPOSE[@]}" logs --no-color --tail=30 app gateway redis >&2 || true
    printf '=== End diagnostics ===\n' >&2
  fi
  exit "$status"
}
trap on_exit EXIT

case "$MODE" in
  redis|http|monitoring|core|all) ;;
  *) echo "Usage: bash tests/run-integration.sh [redis|http|monitoring|core|all]"; exit 2 ;;
esac

[[ -f .env.local && -f docker-compose.dev.yml ]] ||
  fail "Local .env.local / docker-compose.dev.yml not found"

command -v docker >/dev/null || fail "Docker CLI is missing"
command -v python >/dev/null || fail "Python is required for local-only configuration guard and JSON tests"
if [[ "$MODE" != "redis" ]]; then
  command -v curl >/dev/null ||
    fail "curl is required for local HTTPS readiness checks"
fi
"${COMPOSE[@]}" config --quiet || fail "Invalid local Docker Compose configuration"
diagnostics_enabled=1

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

check_healthy() {
  local service="$1" id status attempt
  id="$("${COMPOSE[@]}" ps -q "$service")"
  [[ -n "$id" ]] || fail "Local $service container is not running"

  # Allow an already-started service a short grace period to finish its
  # configured Docker health check; do not start or recreate any service.
  for attempt in {1..40}; do
    status="$(docker inspect --format \
      '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' \
      "$id" 2>/dev/null || true)"
    [[ "$status" == "healthy" ]] && {
      printf 'PASS: %s container is healthy\n' "$service"
      return 0
    }
    [[ "$status" == "unhealthy" ]] &&
      fail "$service container healthcheck reports unhealthy"
    sleep 2
  done
  fail "$service did not become healthy (last status: ${status:-unknown})"
}

run_one() {
  local name="$1"
  local path="$2"
  [[ -f "$path" ]] || fail "Missing integration script: $path"
  printf '\n=== %s ===\n' "$name"
  bash "$path"
}

needs_redis=false
needs_app=false
needs_gateway=false
needs_monitoring=false
case "$MODE" in
  redis) needs_redis=true ;;
  http) needs_redis=true; needs_app=true; needs_gateway=true ;;
  monitoring) needs_app=true; needs_gateway=true; needs_monitoring=true ;;
  core) needs_redis=true; needs_app=true; needs_gateway=true ;;
  all) needs_redis=true; needs_app=true; needs_gateway=true; needs_monitoring=true ;;
esac

if [[ "$needs_redis" == true ]]; then
  check_healthy redis
  [[ "$(MSYS_NO_PATHCONV=1 "${COMPOSE[@]}" exec -T redis redis-cli --raw PING)" == "PONG" ]] ||
    fail "Local Redis healthcheck passed but Redis PING failed"
fi
if [[ "$needs_app" == true ]]; then
  check_healthy app
fi
if [[ "$needs_gateway" == true ]]; then
  check_healthy gateway
  curl -ksS --max-time 8 --fail https://localhost/health/ -o /dev/null ||
    fail "Local Gateway /health/ is not reachable through HTTPS"
  curl -ksS --max-time 8 --fail https://localhost/userbase/ -o /dev/null ||
    fail "Local Gateway /userbase/ is not reachable through HTTPS"
fi
if [[ "$needs_monitoring" == true ]]; then
  [[ -n "$("${COMPOSE[@]}" --profile monitoring ps -q prometheus)" ]] ||
    fail "Prometheus not started (start the monitoring profile)"
  [[ -n "$("${COMPOSE[@]}" --profile monitoring ps -q grafana)" ]] ||
    fail "Grafana not started (start the monitoring profile)"
  curl -fsS --max-time 5 http://127.0.0.1:9090/-/ready -o /dev/null ||
    fail "Prometheus readiness endpoint is not ready"
  curl -fsS --max-time 5 http://127.0.0.1:3000/api/health -o /dev/null ||
    fail "Grafana health endpoint is not ready"
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
  run_one "Django login and brute-force lockout" nginx/tests/test_brute_force_login_live.sh
  ((count+=1))
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
