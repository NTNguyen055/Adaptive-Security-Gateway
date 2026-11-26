#!/usr/bin/env bash
# Repeatable offline regressions against the images built in Jenkins.
# No .env.local, MySQL, Redis, Docker Compose, or network needed.
set -Eeuo pipefail

: "${APP_IMAGE:?Jenkins must supply APP_IMAGE}"
: "${GW_IMAGE:?Jenkins must supply GW_IMAGE}"
: "${IMAGE_TAG:?Jenkins must supply IMAGE_TAG}"

command -v docker >/dev/null || { echo 'FAILED: Docker CLI missing' >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Every suite is an isolated LuaJIT process with mocked dependencies.
# Mount only code and tests from the currently checked-out commit.
lua_tests=(
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
  'test_gateway_fault_guard:gateway_fault_guard'
)

# Docker CLI talks to the host Docker Engine through the socket.
# Translate Jenkins container paths to paths visible on the Docker host.
DOCKER_WORKSPACE_ROOT="$ROOT"

if [ -n "${WORKSPACE:-}" ] && [ -n "${JENKINS_HOME:-}" ]; then
  case "$WORKSPACE" in
    "$JENKINS_HOME"/*)
      JENKINS_HOST_HOME="$(
        docker inspect \
          --format '{{range .Mounts}}{{if eq .Destination "/var/jenkins_home"}}{{.Source}}{{end}}{{end}}' \
          asg-jenkins 2>/dev/null || true
      )"

      if [ -n "$JENKINS_HOST_HOME" ]; then
        DOCKER_WORKSPACE_ROOT="${JENKINS_HOST_HOME}${WORKSPACE#"$JENKINS_HOME"}"
      fi
      ;;
  esac
fi

DOCKER_TESTS_DIR="${DOCKER_WORKSPACE_ROOT}/nginx/tests"
DOCKER_LUA_DIR="${DOCKER_WORKSPACE_ROOT}/nginx/lua"

printf '\n=== OpenResty LuaJIT regression (%d suites) ===\n' \
  "${#lua_tests[@]}"

suites=0
total=0

for pair in "${lua_tests[@]}"; do
  test_name="${pair%%:*}"
  source_name="${pair#*:}"

  printf '\n--- %s ---\n' "$test_name"

  extra_env=()

  if [[ "$test_name" == "test_telegram_alert" ]]; then
    extra_env=(
      -e TELEGRAM_BOT_TOKEN=asg-ci-synthetic-token
      -e TELEGRAM_CHAT_ID=0
    )
  fi

  if ! output="$(
    docker run --rm --network none \
      --workdir /asg \
      --mount "type=bind,source=${DOCKER_TESTS_DIR},target=/asg/nginx/tests,readonly" \
      --mount "type=bind,source=${DOCKER_LUA_DIR},target=/asg/nginx/lua,readonly" \
      -e 'LUA_PATH=/asg/nginx/lua/?.lua;;' \
      "${extra_env[@]}" \
      --entrypoint /usr/local/openresty/luajit/bin/luajit \
      "${GW_IMAGE}:${IMAGE_TAG}" \
      "/asg/nginx/tests/${test_name}.lua" \
      "/asg/nginx/lua/${source_name}.lua" 2>&1
  )"; then
    printf '%s\n' "$output" >&2
    printf 'FAIL: %s exited nonzero\n' "$test_name" >&2
    exit 1
  fi

  printf '%s\n' "$output"
  summary="${output##*$'\n'}"

  if [[ "$summary" =~ ([0-9]+)[[:space:]]passed,[[:space:]]([0-9]+)[[:space:]]failed ]]; then
    cases="${BASH_REMATCH[1]}"
    failures="${BASH_REMATCH[2]}"

    if (( 10#$failures != 0 )); then
      printf 'FAIL: %s reported failed cases\n' "$test_name" >&2
      exit 1
    fi
  elif [[ "$summary" =~ ^([0-9]+)[[:space:]]+.*tests[[:space:]]PASS$ ]]; then
    cases="${BASH_REMATCH[1]}"
  else
    printf 'FAIL: %s has no recognized test summary\n' "$test_name" >&2
    exit 1
  fi

  (( 10#$cases > 0 )) || {
    printf 'FAIL: %s reported zero test cases\n' "$test_name" >&2
    exit 1
  }

  suites=$((suites + 1))
  total=$((total + 10#$cases))
done

printf '\nGateway CI regression: %d suites, %d cases PASS\n' \
  "$suites" "$total"

# settings_test extends settings_local but replaces MySQL and Redis with
# isolated, in-memory backends. Dummy values satisfy startup validation only.
printf '\n=== Django in-memory unit regression ===\n'
docker run --rm --network none \
  -e APP_ENV=local \
  -e USE_DOTENV=False \
  -e USE_S3=False \
  -e SECRET_KEY=ci-only-dummy-secret-never-use-in-production-2026 \
  -e JWT_SECRET_KEY=ci-only-dummy-jwt-key-never-use-in-production-2026 \
  -e ALLOWED_HOSTS=localhost \
  -e DB_HOST=localhost \
  -e DB_NAME=unused_ci_db \
  -e DB_USER=unused_ci_user \
  -e DB_PASSWORD=unused_ci_password \
  --entrypoint python \
  "${APP_IMAGE}:${IMAGE_TAG}" \
  manage.py test docappsystem.tests \
  --settings=docappsystem.settings_test --noinput --verbosity=1

printf '\nJENKINS OFFLINE REGRESSION: PASS\n'
