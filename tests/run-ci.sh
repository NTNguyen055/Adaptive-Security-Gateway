#!/usr/bin/env bash
# Repeatable offline regressions against the images built in Jenkins.
# No .env.local, MySQL, Redis, Docker Compose, or network needed.
set -Eeuo pipefail

: "${APP_IMAGE:?Jenkins must supply APP_IMAGE}"
: "${GW_IMAGE:?Jenkins must supply GW_IMAGE}"
: "${IMAGE_TAG:?Jenkins must supply IMAGE_TAG}"

command -v docker >/dev/null || { echo 'FAIL: Docker CLI missing' >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Every suite is an isolated LuaJIT process with mocked dependencies.
# Mount only code and tests from the currently checked-out commit.
lua_tests=(
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

printf '\n=== OpenResty LuaJIT regression (10 suites) ===\n'
for pair in "${lua_tests[@]}"; do
  test_name="${pair%%:*}"
  source_name="${pair#*:}"
  printf '\n--- %s ---\n' "$test_name"
  docker run --rm --network none \
    --mount "type=bind,source=${DOCKER_TESTS_DIR},target=/asg-tests,readonly" \
    --mount "type=bind,source=${DOCKER_LUA_DIR},target=/asg-lua,readonly" \
    --entrypoint /usr/local/openresty/luajit/bin/luajit \
    "${GW_IMAGE}:${IMAGE_TAG}" \
    "/asg-tests/${test_name}.lua" "/asg-lua/${source_name}.lua"
done

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
