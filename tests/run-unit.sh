#!/usr/bin/env bash
# Gateway/Django repeatable offline unit regression suite (Windows Git Bash friendly).
# Usage: bash tests/run-unit.sh [gateway|django|all]
# Tests do not write to live Redis or MySQL. Django uses an isolated SQLite DB.
set -Eeuo pipefail

mode="${1:-all}"
case "$mode" in
  gateway|django|all) ;;
  *) printf 'Usage: bash tests/run-unit.sh [gateway|django|all]\n' >&2; exit 2 ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

compose=(docker compose --env-file .env.local -f docker-compose.dev.yml)
remote=/tmp/asg-unit-regression
luajit=/usr/local/openresty/luajit/bin/luajit

gateway_suite() {
  printf '\n=== Gateway LuaJIT offline regression ===\n'
  MSYS_NO_PATHCONV=1 docker exec openresty_gateway mkdir -p "$remote/lua" "$remote/tests"
  MSYS_NO_PATHCONV=1 docker cp 'nginx/lua/.' "openresty_gateway:$remote/lua/"
  MSYS_NO_PATHCONV=1 docker cp 'nginx/tests/.' "openresty_gateway:$remote/tests/"

  local pairs=(
    'test_ip_blacklist:ip_blacklist'
    'test_jwt_auth:jwt_auth'
    'test_metrics_labels:metrics_labels'
    'test_rate_limit:rate_limit'
    'test_rate_limit_redis:rate_limit_redis'
    'test_rate_only_guard:risk_engine'
    'test_risk_decay:risk_engine'
    'test_risk_engine:risk_engine'
    'test_risk_redis_failure:risk_engine'
    'test_risk_reputation_ttl:risk_engine'
  )
  local suites=0 total=0 entry test_name source_name output
  for entry in "${pairs[@]}"; do
    test_name="${entry%%:*}"
    source_name="${entry#*:}"
    printf '\n--- %s ---\n' "$test_name"
    # The source under test comes from the current working tree, not an old image layer.
    if ! output="$(MSYS_NO_PATHCONV=1 docker exec openresty_gateway "$luajit" \
      "$remote/tests/$test_name.lua" "$remote/lua/$source_name.lua" 2>&1)"; then
      printf '%s\n' "$output" >&2
      printf 'FAIL: %s (nonzero process exit)\n' "$test_name" >&2
      return 1
    fi
    printf '%s\n' "$output"
    if [[ "$output" =~ ([0-9]+)[[:space:]]passed,[[:space:]]([0-9]+)[[:space:]]failed ]]; then
      if (( 10#${BASH_REMATCH[2]} != 0 )); then
        printf 'FAIL: %s reported failed cases\n' "$test_name" >&2
        return 1
      fi
      total=$((total + 10#${BASH_REMATCH[1]}))
      suites=$((suites + 1))
    else
      printf 'FAIL: %s did not print the expected PASS/FAIL summary\n' "$test_name" >&2
      return 1
    fi
  done
  printf '\nGateway offline regressions: %s suites, %s cases PASS\n' "$suites" "$total"
}

django_suite() {
  printf '\n=== Django isolated unit regression (in-memory SQLite) ===\n'
  # --no-deps means this command neither starts nor changes Redis / MySQL services.
  # --settings overrides the app service's default DJANGO_SETTINGS_MODULE.
  "${compose[@]}" run --rm --no-deps app \
    python manage.py test docappsystem.tests \
      --settings=docappsystem.settings_test --noinput --verbosity=1
  printf 'Django isolated regression: PASS\n'
}

if [[ "$mode" == gateway || "$mode" == all ]]; then gateway_suite; fi
if [[ "$mode" == django || "$mode" == all ]]; then django_suite; fi
printf '\nUNIT REGRESSION RUNNER: PASS (%s)\n' "$mode"
