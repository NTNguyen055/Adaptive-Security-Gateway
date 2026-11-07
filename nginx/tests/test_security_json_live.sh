#!/usr/bin/env bash
# Live JSON security access-log integration test (read-only except one HTTP request).
# Run from repository root, after rebuilding/recreating gateway with Batch 2 config.
set -Eeuo pipefail

COMPOSE=(docker compose --env-file .env.local -f docker-compose.dev.yml)
LOG_PATH=/usr/local/openresty/nginx/logs/security.json.log
PROBE="asg_stage16_json_${$}_$(date +%s)"
TEST_PATH="/__${PROBE}/"
QUERY_CANARY="query_secret_${PROBE}_end"
TEST_AGENT='ASG-Probe "quoted" \ slash'
TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT

# This URL's query contains a synthetic secret. The security access log must
# record only the normalized path, never this query string.
TEST_URL="https://localhost${TEST_PATH}?demo_secret=${QUERY_CANARY}"
STATUS="$(curl -ksS --max-time 10 -A "$TEST_AGENT" -o /dev/null -w '%{http_code}' "$TEST_URL")"
echo "Probe HTTP status: $STATUS"
if [[ "$STATUS" != '403' ]]; then
    echo 'FAIL: expected HTTP 403 for unauthenticated probe' >&2
    exit 1
fi

# An access-log line is buffered per Nginx worker. A fixed sleep can race
# with the worker flush and cause a false negative. Poll the unique probe
# path instead; a matching line is sufficient for the assertions below.
FOUND=0
for attempt in {1..15}; do
    MSYS_NO_PATHCONV=1 "${COMPOSE[@]}" exec -T gateway sh -c \
        "grep -F '$TEST_PATH' '$LOG_PATH' || true" > "$TMP_FILE"
    if [[ -s "$TMP_FILE" ]]; then
        FOUND=1
        break
    fi
    sleep 2
done
if [[ "$FOUND" -ne 1 ]]; then
    echo "FAIL: no JSON log entry for probe after 15 polling attempts: $TEST_PATH" >&2
    exit 1
fi
# Pass the probe ID, not the leading-slash URI, as a Python argument.
# Git Bash/MSYS2 can rewrite arguments beginning with '/' for Windows Python.
# The JSON path is constructed inside Python, so Windows path conversion
# cannot corrupt the expected URI. Leave TMP_FILE conversion intact.
python - "$TMP_FILE" "$PROBE" "$QUERY_CANARY" "$TEST_AGENT" <<'PYTHON'
import json, sys
from pathlib import Path
file_path, probe, secret, agent = sys.argv[1:]
expected_path = "/__" + probe + "/"
raw = Path(file_path).read_text(encoding='utf-8', errors='replace').splitlines()
if not raw:
    raise SystemExit('FAIL: no log record returned for probe')

matches=[]
for idx, line in enumerate(raw, 1):
    try:
        record = json.loads(line)
    except json.JSONDecodeError as exc:
        raise SystemExit(f'FAIL: invalid JSON line {idx}: {exc}')
    if record.get('path') == expected_path:
        matches.append((record, line))

if len(matches) != 1:
    candidates=[]
    for line in raw[:5]:
        try:
            candidates.append(json.loads(line).get('path'))
        except json.JSONDecodeError:
            candidates.append('<invalid JSON>')
    raise SystemExit(
        f'FAIL: expected exactly 1 probe log entry, got {len(matches)}; '
        f'expected path: {expected_path!r}; observed paths: {candidates!r}'
    )
obj, line=matches[0]
required={'timestamp', 'request_id', 'client_ip', 'method', 'path',
          'status', 'action', 'reason', 'risk_score',
          'request_time_seconds', 'upstream_time_seconds', 'user_agent'}
assert required.issubset(obj), f'Missing fields: {required-set(obj)}'
assert obj['status']==403, obj
assert obj['method']=='GET', obj
assert obj['action']=='block', obj
assert obj['reason']=='jwt_missing', obj
assert obj['request_id'] and obj['timestamp'], obj
assert obj['client_ip'], obj
assert isinstance(obj['risk_score'], (int, float)), obj
assert isinstance(obj['request_time_seconds'], (int, float)), obj
assert obj['user_agent']==agent, (obj['user_agent'],agent)
assert secret not in line, 'Sensitive query parameter leaked into access log'
assert '?' not in obj['path'], 'Query present in path'
print('PASS: JSON log parses and includes all required fields')
print('PASS: HTTP 403, action=block, reason=jwt_missing')
print('PASS: numeric risk and latency; request ID recorded')
print('PASS: quoted/backslash user agent safely escaped')
print('PASS: request query/secret not written to security JSON log')
print('JSON security log live tests: 5 passed, 0 failed, 5 total')
PYTHON
