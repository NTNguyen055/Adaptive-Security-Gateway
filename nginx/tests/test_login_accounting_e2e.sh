#!/usr/bin/env bash
# P0.2.3-D3.3-F — local-only HTTP concurrency / lockout test.
# Must run from the root of Adaptive-Security-Gateway in Git Bash.
# Requires docker-compose.dev.yml, docker-compose.p02-e2e.yml, .env.local.
# Does NOT change source or .env.local; restores flag OFF on exit.
set -Eeuo pipefail

for file in docker-compose.dev.yml docker-compose.p02-e2e.yml .env.local; do
  if [[ ! -f "$file" ]]; then
    echo "ERROR: Missing $file in current directory" >&2
    exit 1
  fi
done
command -v docker >/dev/null

BASE=(docker compose --env-file .env.local -f docker-compose.dev.yml)
E2E=(docker compose --env-file .env.local -f docker-compose.dev.yml -f docker-compose.p02-e2e.yml)
CLIENT="p02-e2e-client-$(date +%s)-${RANDOM}"
IP=""
CAN_CLEAN_KEYS=0
NEED_ROLLBACK=0

redis() {
  "${BASE[@]}" exec -T redis redis-cli --raw -n 0 "$@" | tr -d '\r'
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  echo
  echo "=== CLEANUP: isolated security keys and disposable client ==="
  if [[ "$CAN_CLEAN_KEYS" == 1 && -n "$IP" ]]; then
    redis DEL \
      "brute_force:fail:$IP" \
      "brute_force:lockout:$IP" \
      "blacklist:$IP" \
      "brute_force:history:$IP" \
      "brute_force:success:$IP" \
      "risk:v1:$IP" \
      "bf:v2:active:$IP" >/dev/null || true
    echo "Only test-IP keys were removed; expiring bf:v2:req:<token> keys are left to TTL."
  fi
  docker rm -f "$CLIENT" >/dev/null 2>&1 || true
  if [[ "$NEED_ROLLBACK" == 1 ]]; then
    echo "=== ROLLBACK: local feature flag OFF; restore Gateway environment ==="
    if ! "${BASE[@]}" up -d --no-deps --force-recreate --wait app; then
      echo "CRITICAL: App rollback failed. Restore it with base Compose manually." >&2
      status=1
    fi
    if ! "${BASE[@]}" up -d --no-deps --force-recreate --wait gateway; then
      echo "CRITICAL: Gateway rollback failed. Restore it with base Compose manually." >&2
      status=1
    fi
    echo "=== RESTORED RUNTIME FLAG ==="
    local restored_flag
    restored_flag=$("${BASE[@]}" exec -T app python -c \
      'from django.conf import settings; print(settings.LOGIN_ACCOUNTING_ENABLED)' 2>/dev/null | tr -d '\r\n')
    echo "LOGIN_ACCOUNTING_ENABLED = $restored_flag"
    if [[ "$restored_flag" != False ]]; then
      echo "CRITICAL: Flag was not confirmed OFF after rollback" >&2
      status=1
    fi
  fi
  if [[ "$status" -eq 0 ]]; then
    echo "PASS: D3.3-F local concurrent login E2E"
  else
    echo "FAIL/ABORT: D3.3-F (exit $status); check output and rollback above" >&2
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

initial_flag=$("${BASE[@]}" exec -T app python -c \
  'from django.conf import settings; print(settings.LOGIN_ACCOUNTING_ENABLED)' | tr -d '\r\n')
if [[ "$initial_flag" != "False" ]]; then
  echo "STOP: Expected running app flag False, got '$initial_flag'." >&2
  exit 1
fi

base_flag=$("${BASE[@]}" run --rm -T --no-deps app python -c \
  'from django.conf import settings; print(settings.LOGIN_ACCOUNTING_ENABLED)' | tail -n 1 | tr -d '\r\n')
if [[ "$base_flag" != "False" ]]; then
  echo "STOP: Base Compose must also have flag False for safe rollback (got '$base_flag')." >&2
  exit 1
fi

echo "=== E2E: Bring Gateway up first (Telegram disabled locally) ==="
NEED_ROLLBACK=1
"${E2E[@]}" up -d --no-deps --force-recreate --wait gateway

echo "=== E2E: Bring app up with LOGIN_ACCOUNTING_ENABLED=True ==="
"${E2E[@]}" up -d --no-deps --force-recreate --wait app
runtime_flag=$("${E2E[@]}" exec -T app python -c \
  'from django.conf import settings; print(settings.LOGIN_ACCOUNTING_ENABLED)' | tr -d '\r\n')
if [[ "$runtime_flag" != "True" ]]; then
  echo "STOP: Expected True in running app, got '$runtime_flag'" >&2
  exit 1
fi

"${E2E[@]}" exec -T gateway sh -c \
  'grep -q "X-Login-Accounting" /usr/local/openresty/nginx/conf/nginx.conf && grep -q "X-Login-Alert" /usr/local/openresty/nginx/conf/nginx.conf'

health=$(curl -k -sS --max-time 10 -o /dev/null -w '%{http_code}' https://localhost/health/)
[[ "$health" == 200 ]] || { echo "STOP: /health/ returned $health"; exit 1; }

echo "=== E2E: Start disposable Docker client (unique source IP) ==="
"${E2E[@]}" run -d --no-deps --name "$CLIENT" --entrypoint sh gateway -c 'sleep 600' >/dev/null
IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CLIENT")
[[ "$IP" =~ ^172\.20\.0\.[0-9]+$ ]] || { echo "STOP: Unexpected client IP '$IP'"; exit 1; }
echo "Isolated test client IP: $IP"

keys=(
  "brute_force:fail:$IP" "brute_force:lockout:$IP"
  "blacklist:$IP" "brute_force:history:$IP"
  "brute_force:success:$IP" "risk:v1:$IP" "bf:v2:active:$IP"
)
if [[ "$(redis EXISTS "${keys[@]}")" != 0 ]]; then
  echo "STOP: Existing Redis keys for test client IP; will not overwrite or delete them." >&2
  exit 1
fi
CAN_CLEAN_KEYS=1

# Verify the gateway sees THIS container IP, not a Docker NAT/shared address.
# Otherwise the test could lock the wrong source IP.
echo "=== VERIFY CLIENT IP TRUST BEFORE WRONG-PASSWORD REQUESTS ==="
precheck_http=$(docker exec "$CLIENT" curl -k -sS --max-time 10 \
  -A "p02-e2e-$CLIENT" -H "Host: localhost" \
  -o /dev/null -w '%{http_code}' https://gateway/login/)
[[ "$precheck_http" == 200 ]] || { echo "STOP: Test client GET login HTTP $precheck_http"; exit 1; }
sleep 6
observed=$("${E2E[@]}" exec -T gateway sh -c \
  "grep -F '\"user_agent\":\"p02-e2e-$CLIENT\"' /usr/local/openresty/nginx/logs/security.json.log | tail -n 1" \
  | sed -n 's/.*"client_ip":"\([^"]*\)".*/\1/p' | tr -d '\r')
echo "Client container IP: $IP; Gateway logged IP: $observed"
[[ "$observed" == "$IP" ]] || { echo "STOP: IP trust precheck failed; no attack requests sent"; exit 1; }

# One same-source-IP client performs eight real, valid-CSRF HTTP logins.
# Each uses an unknown email, never a real account. No real Telegram delivery.
echo "=== E2E: 8 concurrent valid-CSRF wrong logins, budget=5 ==="
docker exec -e TEST_EMAIL="p02-e2e-$(date +%s)-$RANDOM@example.invalid" "$CLIENT" sh -ec '
  curl -kfsS --max-time 12 -H "Host: localhost" \
       -c /tmp/p02.cookies -b /tmp/p02.cookies \
       -o /tmp/p02-login.html https://gateway/login/
  token=$(sed -n '\''s/.*name="csrfmiddlewaretoken" value="\([^" ]*\)".*/\1/p'\'' /tmp/p02-login.html | head -n 1)
  test -n "$token" || { echo "STOP: CSRF hidden token missing"; exit 1; }
  for i in 1 2 3 4 5 6 7 8; do
    (
      curl -k -sS --max-time 15 \
        -H "Host: localhost" \
        --referer https://localhost/login/ \
        -b /tmp/p02.cookies \
        --data-urlencode "csrfmiddlewaretoken=$token" \
        --data-urlencode "email=$TEST_EMAIL" \
        --data-urlencode "password=not-a-valid-password" \
        -D "/tmp/p02.h.$i" -o /dev/null \
        -w "%{http_code}\n" \
        https://gateway/doLogin/ > "/tmp/p02.s.$i"
    ) &
  done
  wait
  echo "HTTP status distribution:"
  cat /tmp/p02.s.* | sort | uniq -c
  admitted=$(cat /tmp/p02.s.* | grep -c "^302$" || true)
  denied=$(cat /tmp/p02.s.* | grep -Ec "^(403|429)$" || true)
  [ "$admitted" -eq 5 ] && [ "$denied" -eq 3 ] || {
    echo "FAIL: Expected 5x302 + 3x(403/429), got $admitted / $denied";
    exit 1;
  }
  if grep -iEq "^x-login-(status|accounting|alert):" /tmp/p02.h.*; then
    echo "FAIL: Internal response header leaked"; exit 1
  fi
  echo "PASS: Exactly 5 authentication responses, 3 blocked; no internal header leakage"
  blocked=$(curl -k -sS --max-time 10 -H "Host: localhost" \
    -o /dev/null -w "%{http_code}" https://gateway/login/)
  echo "GET /login/ after lockout: $blocked"
  [ "$blocked" = 403 ] || exit 1
'

sleep 2
count=$(redis GET "brute_force:fail:$IP")
lockout=$(redis GET "brute_force:lockout:$IP")
blacklist=$(redis GET "blacklist:$IP")
active=$(redis ZCARD "bf:v2:active:$IP")
history=$(redis GET "brute_force:history:$IP")
history_count=$(awk -F, '{print NF}' <<< "$history")

echo "=== REDIS CHECK (test IP only) ==="
echo "failed counter: $count (expected 5)"
echo "lockout: $lockout (expected 1)"
echo "blacklist: $blacklist (expected 1)"
echo "active reservations: $active (expected 0)"
echo "history events: $history_count (expected 5)"
[[ "$count" == 5 && "$lockout" == 1 && "$blacklist" == 1 && \
   "$active" == 0 && "$history_count" == 5 ]] || exit 1

echo "PASS: Redis accounting and block state are consistent"
