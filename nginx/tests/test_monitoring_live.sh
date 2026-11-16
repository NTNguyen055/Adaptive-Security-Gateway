#!/usr/bin/env bash
# Stage 1.6 Batch 3: Verify Prometheus and Grafana locally (Windows Git Bash safe).
# Requires the 'monitoring' Compose profile already started.
set -Eeuo pipefail

PROM_URL=http://127.0.0.1:9090
GRAFANA_URL=http://127.0.0.1:3000
COMPOSE=(docker compose --profile monitoring --env-file .env.local -f docker-compose.dev.yml)
TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# Prometheus may need a few seconds to start after docker compose up.
READY=0
for attempt in {1..20}; do
    if curl -fsS --max-time 4 "$PROM_URL/-/healthy" > /dev/null 2>&1; then
        READY=1; break
    fi
    sleep 3
done
[[ "$READY" == 1 ]] || fail 'Prometheus health endpoint not ready'
echo 'PASS: Prometheus HTTP health'

READY=0
for attempt in {1..20}; do
    if curl -fsS --max-time 4 "$GRAFANA_URL/api/health" > "$TMP_FILE" 2>/dev/null &&
       python - "$TMP_FILE" <<'PY_CHECK' > /dev/null
import json,sys
with open(sys.argv[1],encoding='utf-8') as f: data=json.load(f)
assert data.get('database') == 'ok', data
PY_CHECK
    then
        READY=1; break
    fi
    sleep 3
done
[[ "$READY" == 1 ]] || fail 'Grafana health endpoint not ready'
echo 'PASS: Grafana HTTP health and database'

# Must verify successful Prometheus scrape, not merely service is running.
UP=0
for attempt in {1..20}; do
    if curl -fsS --max-time 5 "$PROM_URL/api/v1/targets?state=active" > "$TMP_FILE" 2>/dev/null &&
       python - "$TMP_FILE" <<'PY_CHECK' > /dev/null
import json,sys
with open(sys.argv[1],encoding='utf-8') as f: doc=json.load(f)
assert doc.get('status') == 'success'
targets=doc['data'].get('activeTargets',[])
assert any(t.get('labels',{}).get('job')=='adaptive_security_gateway'
           and t.get('health')=='up' for t in targets), targets
PY_CHECK
    then
        UP=1; break
    fi
    sleep 3
done
[[ "$UP" == 1 ]] || fail 'Gateway target is not UP in Prometheus'
echo 'PASS: Prometheus scrapes Gateway target successfully'

# Generate both HTTP statuses for metrics; avoid printing any authentication data.
STATUS_PUBLIC="$(curl -ksS --max-time 10 -o /dev/null -w '%{http_code}' https://localhost/userbase/)"
STATUS_REJECT="$(curl -ksS --max-time 10 -o /dev/null -w '%{http_code}' https://localhost/gateway-jwt-probe/)"
[[ "$STATUS_PUBLIC" == '200' ]] || fail "public endpoint expected 200, got $STATUS_PUBLIC"
[[ "$STATUS_REJECT" == '403' ]] || fail "JWT probe expected 403, got $STATUS_REJECT"
echo 'PASS: Gateway 200/403 probes'

# Validate actual Prometheus series labels. The job and instance labels added by
# Prometheus are expected; unbounded client IP or Host labels are not.
check_series() {
    local metric="$1"
    local expected_label="$2"
    curl -fsSG --max-time 5 \
      --data-urlencode "query=$metric" \
      "$PROM_URL/api/v1/query" > "$TMP_FILE" 2>/dev/null || return 1
    python - "$TMP_FILE" "$metric" "$expected_label" <<'PY_CHECK' > /dev/null
import json,sys
file_path, metric, required = sys.argv[1:]
with open(file_path,encoding='utf-8') as f: doc=json.load(f)
assert doc.get('status')=='success',doc
results=doc['data'].get('result',[])
assert results, f'{metric}: no data yet'
for item in results:
    labels=item.get('metric',{})
    assert labels.get('__name__')==metric, labels
    assert required in labels, labels
    assert 'ip' not in labels and 'host' not in labels, labels
PY_CHECK
}
SERIES_OK=0
for attempt in {1..20}; do
    if check_series nginx_http_requests_total status &&
       check_series nginx_security_decisions_total reason; then
        SERIES_OK=1; break
    fi
    sleep 3
done
[[ "$SERIES_OK" == '1' ]] || fail 'Metrics absent after scrape or contain unbounded labels'
echo 'PASS: HTTP and security metrics are available without IP/Host labels'

# Check provisioning files are visible inside the running Grafana container.
MSYS_NO_PATHCONV=1 "${COMPOSE[@]}" exec -T grafana sh -c \
 'test -s /etc/grafana/provisioning/datasources/prometheus.yml && \
  test -s /etc/grafana/provisioning/dashboards/dashboards.yml && \
  test -s /var/lib/grafana/dashboards/asg-overview.json' \
 || fail 'Grafana provisioning files are not mounted'
echo 'PASS: Grafana datasource and dashboard files are mounted'

echo 'Monitoring live tests: 6 passed, 0 failed, 6 total'
echo 'Open http://127.0.0.1:3000/d/asg-security-overview and verify panels in the UI.'
