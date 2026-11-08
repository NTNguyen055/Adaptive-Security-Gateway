#!/usr/bin/env bash
# Local-only bounded Gateway load probe. Does not modify code or Redis manually.
# Run in Git Bash: bash tests/run-load.sh
set -Eeuo pipefail
export MSYS_NO_PATHCONV=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
COMPOSE=(docker compose --env-file .env.local -f docker-compose.dev.yml)
fail() { echo "FAIL: $*" >&2; exit 1; }

command -v docker >/dev/null || fail 'Docker CLI missing'
command -v python >/dev/null || fail 'Host Python missing'
[[ -f .env.local && -f tests/helpers/load-client.py ]] || fail 'Missing .env.local or load client script'
"${COMPOSE[@]}" config --quiet || fail 'Invalid local Compose configuration'
"${COMPOSE[@]}" config --format json | python -c '
import json,sys
c=json.load(sys.stdin)
assert c.get("name")=="adaptive-security-local", "Not the local Compose project"
p=c["services"]["gateway"].get("ports",[])
assert p and all(x.get("host_ip") in ("127.0.0.1","::1") for x in p), "Gateway must bind loopback"
print("PASS: local-only Compose guard")
' || fail 'Refusing to run load against a non-local Compose stack'

gateway_id="$("${COMPOSE[@]}" ps -q gateway)"
[[ -n "$gateway_id" ]] || fail 'Local gateway container is not running'
[[ "$("${COMPOSE[@]}" exec -T redis redis-cli --raw PING)" == PONG ]] || fail 'Local Redis not ready'
docker image inspect adaptive-security-app:local >/dev/null 2>&1 || fail 'Local app Docker image not found'
network="$(docker inspect "$gateway_id" --format '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' | head -n 1)"
[[ -n "$network" ]] || fail 'Could not determine local Gateway network'
subnet="$(docker network inspect "$network" --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}')"
[[ "$subnet" == '172.20.0.0/24' ]] || fail "Unexpected local Docker subnet: $subnet"

# Fresh client IP per run: do not reuse rate-limiter state from recent tests.
# IPs 172.20.0.200-239 are reserved for these short-lived load clients.
in_use="$(docker network inspect "$network" --format '{{range .Containers}}{{println .IPv4Address}}{{end}}')"
client_ip=''
for attempt in {1..40}; do
  candidate="172.20.0.$((200 + RANDOM % 40))"
  if grep -qF "${candidate}/" <<< "$in_use"; then continue; fi
  [[ "$("${COMPOSE[@]}" exec -T redis redis-cli --raw EXISTS "rrl:${candidate}")" == 0 ]] || continue
  [[ "$("${COMPOSE[@]}" exec -T redis redis-cli --raw EXISTS "blacklist:${candidate}")" == 0 ]] || continue
  [[ "$("${COMPOSE[@]}" exec -T redis redis-cli --raw SISMEMBER blacklist_ips "$candidate")" == 0 ]] || continue
  client_ip="$candidate"; break
done
[[ -n "$client_ip" ]] || fail 'No fresh load-test client IP available; wait for TTL expiry'

test_id="asg-load-probe-$$"
# Refuse to alter an existing container if a generated name ever collides.
if docker container inspect "$test_id" >/dev/null 2>&1; then
  fail "Disposable client container name is already in use: $test_id"
fi
# Native Windows Python cannot read Git Bash /tmp paths. Keep the transient log
# under the repo so paths stay relative and platform-independent.
mkdir -p tests/results
logfile="$(mktemp tests/results/.load-stdout.XXXXXX)"
cleanup() { rm -f "$logfile"; docker rm -f "$test_id" >/dev/null 2>&1 || true; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

commit="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
report="tests/results/load-$(date +%Y%m%d-%H%M%S)-$$.json"
echo "Isolated load client: $client_ip | 61 requests total | peak concurrency 6"
echo 'Baseline 5 requests; concurrent phases 20 and 36 requests.'
status=0
docker run --rm -i --name "$test_id" --network "$network" --ip "$client_ip" \
  -e "ASG_COMMIT=$commit" --entrypoint python \
  adaptive-security-app:local - < tests/helpers/load-client.py > "$logfile" 2>&1 || status=$?
grep -v '^REPORT_JSON=' "$logfile" || true
python - "$logfile" "$report" <<'PY'
import json,sys
from pathlib import Path
raw=Path(sys.argv[1]).read_text(encoding='utf-8',errors='replace').splitlines()
entries=[line[len('REPORT_JSON='):] for line in raw if line.startswith('REPORT_JSON=')]
if len(entries)!=1:
    raise SystemExit('FAIL: load client did not emit exactly one JSON report')
report=json.loads(entries[0])
Path(sys.argv[2]).write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print('Report saved to: '+sys.argv[2])
PY
[[ "$status" -eq 0 ]] || fail "Load test failed (exit=$status); see saved report"
