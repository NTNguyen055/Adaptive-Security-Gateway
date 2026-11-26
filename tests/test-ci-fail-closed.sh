#!/usr/bin/env bash
# P0.4: read-only CI runner failure contract (real Docker is NEVER invoked).
# Exercises the currently checked-out tests/run-ci.sh in an isolated temporary copy.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "$ROOT/tests/run-ci.sh" ]] || {
  printf 'FAIL: expected tests/run-ci.sh at %s\n' "$ROOT" >&2
  exit 2
}

command -v mktemp >/dev/null && command -v bash >/dev/null || {
  printf 'FAIL: bash and mktemp are required\n' >&2
  exit 2
}

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p "$tmp/isolated/tests" "$tmp/bin"
cp -- "$ROOT/tests/run-ci.sh" "$tmp/isolated/tests/run-ci.sh"

# Mock only Docker's CLI, NEVER Docker socket or Jenkins/real images.
# All cases run against a disposable COPY of the actual CI script.
cat > "$tmp/bin/docker" <<'MOCK'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "${1:-}" == run ]] || { echo 'Unexpected Docker operation' >&2; exit 91; }
args="$*"

if [[ "$args" == *'/asg/nginx/tests/test_ip_blacklist.lua'* ]]; then
  case "${ASG_CI_MOCK_MODE:-ok}" in
    summary_failure) printf '0 passed, 1 failed\n'; exit 0 ;;
    nonzero_exit) printf '1 passed, 0 failed\n'; exit 23 ;;
    missing_summary) printf 'No test summary\n'; exit 0 ;;
    zero_cases) printf '0 passed, 0 failed\n'; exit 0 ;;
  esac
fi

if [[ "$args" == *'manage.py test docappsystem.tests'* ]]; then
  printf 'Found 114 test(s).\nOK (skipped=12)\n'
elif [[ "$args" == *'/asg/nginx/tests/test_telegram_alert.lua'* ]]; then
  printf '5 tests PASS\n'
else
  printf '1 passed, 0 failed\n'
fi
MOCK
chmod 700 "$tmp/bin/docker"

passed=0
check() {
  local mode="$1" expected="$2" output='' status=0
  # Explicitly neutralize Jenkins variables, so this test never calls docker inspect.
  output="$(
    PATH="$tmp/bin:$PATH" \
      APP_IMAGE=asg-mock-app \
      GW_IMAGE=asg-mock-gateway \
      IMAGE_TAG=synthetic \
      ASG_CI_MOCK_MODE="$mode" \
      WORKSPACE='' JENKINS_HOME='' \
      bash "$tmp/isolated/tests/run-ci.sh" 2>&1
  )" || status=$?

  if [[ "$expected" == pass ]]; then
    if [[ "$status" -ne 0 ]] \
       || [[ "$output" != *'Gateway CI regression: 18 suites, 22 cases PASS'* ]] \
       || [[ "$output" != *'JENKINS OFFLINE REGRESSION: PASS'* ]]; then
      printf 'FAIL: positive control: exit=%s\n%s\n' "$status" "$output" >&2
      exit 1
    fi
  else
    if [[ "$status" -eq 0 ]] || [[ "$output" != *'FAIL:'* ]] \
       || [[ "$output" == *'JENKINS OFFLINE REGRESSION: PASS'* ]]; then
      printf 'FAIL: %s should fail closed: exit=%s\n%s\n' "$mode" "$status" "$output" >&2
      exit 1
    fi
  fi
  passed=$((passed+1))
  printf 'PASS  %-17s expected=%s actual_exit=%d\n' "$mode" "$expected" "$status"
}

check ok pass
check summary_failure fail
check nonzero_exit fail
check missing_summary fail
check zero_cases fail
printf 'P0.4 isolated CI runner contract: %d passed, 0 failed\n' "$passed"
