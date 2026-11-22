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
    'test_ip_ban_authorizer:ip_ban_authorizer'
    'test_ip_ban_issuer:ip_ban_issuer'
    'test_security_correlator:security_correlator'
    'test_security_policy:security_policy'
    'test_security_shadow:security_shadow'
    'test_security_signal_adapter:security_signal_adapter'
    'test_telegram_alert:telegram_alert'
    'test_brute_force_login:brute_force_login'
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

  local suites=0 total=0 entry test_name source_name
  local output summary cases failures
  local -a extra_env

  for entry in "${pairs[@]}"; do
    test_name="${entry%%:*}"
    source_name="${entry#*:}"

    printf '\n--- %s ---\n' "$test_name"

    extra_env=(
      -e "LUA_PATH=${remote}/lua/?.lua;;"
    )

    if [[ "$test_name" == "test_telegram_alert" ]]; then
      extra_env+=(
        -e TELEGRAM_BOT_TOKEN=asg-local-synthetic-token
        -e TELEGRAM_CHAT_ID=0
      )
    fi

    if ! output="$(
      MSYS_NO_PATHCONV=1 docker exec \
        "${extra_env[@]}" \
        openresty_gateway \
        "$luajit" \
        "$remote/tests/$test_name.lua" \
        "$remote/lua/$source_name.lua" 2>&1
    )"; then
      printf '%s\n' "$output" >&2
      printf 'FAIL: %s exited nonzero\n' "$test_name" >&2
      return 1
    fi

    printf '%s\n' "$output"
    summary="${output##*$'\n'}"

    if [[ "$summary" =~ ([0-9]+)[[:space:]]passed,[[:space:]]([0-9]+)[[:space:]]failed ]]; then
      cases="${BASH_REMATCH[1]}"
      failures="${BASH_REMATCH[2]}"

      if (( 10#$failures != 0 )); then
        printf 'FAIL: %s reported failures\n' "$test_name" >&2
        return 1
      fi
    elif [[ "$summary" =~ ^([0-9]+)[[:space:]]+.*tests[[:space:]]PASS$ ]]; then
      cases="${BASH_REMATCH[1]}"
    else
      printf 'FAIL: %s missing test summary\n' "$test_name" >&2
      return 1
    fi

    (( 10#$cases > 0 )) || {
      printf 'FAIL: %s reported zero cases\n' "$test_name" >&2
      return 1
    }

    suites=$((suites + 1))
    total=$((total + 10#$cases))
  done

  printf '\nGateway offline regressions: %d suites, %d cases PASS\n' \
    "$suites" "$total"
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
