# Gateway — Isolated HTTPS Fault Injection & Enforcement

**Status: harness prepared; runtime acceptance pending.** Python helper tests pass in the preparation environment; Docker/OpenResty runtime has not been executed there. Use the exact local image already accepted in FI-08A and the current working tree. Do not interpret expected values as observations.

## Installation

Extract this archive into the repository root. It adds only these files:

```
tests/gateway_fault_lab/run_lab.py
tests/gateway_fault_lab/fault_worker.lua
tests/gateway_fault_lab/mock_backend.py
tests/gateway_fault_lab/test_lab_helpers.py
docs/GATEWAY_HTTPS_FAULT_LAB.md
```

No edits to existing files, Compose, Jenkinsfile, nginx.conf, or production Lua modules are needed. Do not copy the fixture into `nginx/lua/` or include it in a release image. Do not add a header, endpoint, or environment switch to the production Gateway for fault injection.

## Isolation and reproducibility

- Python >= 3.10 and local Docker CLI/Engine. Uses existing local images only (`--pull never`): Gateway, app (Python interpreter only), Redis (pin from dev Compose). No `.env` or `.env.local` read or passed to any lab container. No real Django or MySQL execution.
- A randomly named Docker `--internal` network holds four disposable roles: mock backend (`docapp_django:8000`), Redis (`redis:6379`), client, and one fresh Gateway per case (`gateway:443`). No published ports, host bind mounts, existing named volumes, or connection to the existing Compose network. Redis is temporary, with persistence disabled. No `FLUSHALL` or production Redis commands. Removal uses only created names and includes anonymous volumes.
- Runner compares the inspected image ID to the recorded FI-08A ID. It compares the baked Nginx configuration and thirteen relevant Lua files with the current working tree (CRLF normalized only for comparison), then records image SHA-256 file digests. If changed, stop and review/rebuild/re-establish baseline; do not blindly override the expected ID.
- Copy of the image's real Nginx configuration: only worker count (1), error log destination (stderr), and a fixed `init_worker_by_lua_block` fixture are changed. The actual six access-phase route blocks, guard, shadow wrapper, and production modules remain in the image. One test case per fresh worker; no request-controlled activation. The single client sends sequential requests and uses `Host: localhost` with a normal browser UA. `curl -k` is for this isolated self-signed certificate only.
- E2E-09 temporarily substitutes the Redis helper only inside the real Redis limiter call; prelogin/blacklist still use isolated healthy Redis. This is a controlled *selective* dependency failure, not a real full Redis outage. E2E-11 injects an established synthetic WAF denial (no payload exploit); E2E-12 uses actual local limiter handling and actual Risk Engine classification before injecting an exception. These tests verify preservation of decisions, not attack detector accuracy.

## Run from Windows Git Bash, repository root

```bash
python --version
python -m unittest discover -s tests/gateway_fault_lab -p 'test_lab_helpers.py' -v

docker image inspect --format '{{.Id}}' adaptive-security-gateway:local

set -o pipefail
python tests/gateway_fault_lab/run_lab.py \
  --expected-image-id sha256:b66323dd2b96e7eebe22733dec25b51addf80ad4ea7b22fa01c51b1a6d4ae9fb \
  --output gateway-fault-lab-results-01 2>&1 | tee gateway-fault-lab-01.log
```

`--output` must be a new directory to prevent evidence overwrites. For another run use `gateway-fault-lab-results-02` and a different log filename. The runner stops on the first failure and attempts cleanup even if a case fails. Inspect `summary.json` and the failing case folder before rerunning. Never delete real Docker containers or volumes to make this lab pass. If cleanup fails, use the exact randomly generated lab label in manifest.json to inspect leftover resources; do not use broad Docker prune commands.

## Expected matrix (not measured yet)

| Case | Route | Injection | HTTP | Upstream delta |
|---|---|---|---:|---:|
| E2E-01 | POST /doLogin/, GET /profile/ | None | 200 each | 1 each |
| E2E-02 | POST /doLogin/ | IP blacklist exception | 503 | 0 |
| E2E-03 | GET /profile/ | WAF exception | 503 | 0 |
| E2E-04 | GET /profile/ | JWT module exception | 503 | 0 |
| E2E-05 | POST /doLogin/ | Bad bot exception | 200 | 1 |
| E2E-06 | POST /doLogin/ | L1 exception, actual Redis L2 | 200 | 1 |
| E2E-07 | POST /doLogin/ | L2 exception, actual L1 | 200 | 1 |
| E2E-08 | POST /doLogin/ | L1 and L2 exceptions | 503 | 0 |
| E2E-09 | POST /doLogin/ | Real L1 init nil and L2 connection nil | 503 | 0 |
| E2E-10 | POST /doLogin/ | Risk Engine exception before decision | 503 | 0 |
| E2E-11 | GET /profile/ | Synthetic hard deny then Risk Engine exception | 403 | 0 |
| E2E-12 | POST /doLogin/ | Real rate-only decision then Risk Engine exception | 429 | 0 |
| E2E-13 | POST /doLogin/, GET /profile/ | Clean fresh worker, same lab backend/Redis | 200 each | 1 each |

The mock upstream responds 200, including `/profile/`; this is deliberate and does not replace the FI-08A Django authorization 302 evidence. The synthetic POST is not a real authentication, does not carry credentials, and does not test CSRF/login accounting at Django. E2E-04 tests failure of the invoked JWT module on a Django-session route, not a protected API token verification. E2E-13 proves clean-worker recovery after removing the hook, not recovery of an already crashed worker or actual Redis reconnection. The 13 cases do not cover every detector failure on every route; FI-06 covers structural integration of all six routes.

## Jenkins CI Integration

The Gateway HTTPS Fault Lab is executed as a mandatory
runtime security gate after the Smoke Test stage and
before image publication or deployment.

The CI pipeline supplies:

- Gateway and application image references built from
  the current source commit.
- Gateway image identity obtained from Docker inspection.
- OCI revision verification for both application images.
- A digest-pinned Redis dependency.
- A unique evidence directory for each execution.

The lab uses an isolated internal Docker network,
a mock upstream backend, and disposable Redis state.

No production environment files, production credentials,
or production services are required.

### CI Acceptance Criteria

- Python helper regression passes.
- Gateway image and source verification passes.
- All 13 HTTPS fault injection scenarios pass.
- Denied requests do not reach the mock backend.
- Redis state remains within the expected test scope.
- Lab cleanup completes without errors.

Any nonzero test runner exit status fails the CI stage
and prevents subsequent publication or deployment stages.

The runner log, source commit, manifest, summary,
HTTP response evidence, Gateway logs, backend logs,
and Redis snapshots are archived as Jenkins artifacts.

Forced termination of the Jenkins agent or Docker daemon
may interrupt automatic cleanup. Any remaining lab resources
must be identified by their exact lab label before removal.

## Acceptance and evidence

- All 13 cases pass: expected status, mock upstream marker header, exact request-count delta from upstream logs. Every intended injected event appears in worker logs and fault guard logs (silent dual case must not become an exception). E2E-06 checks actual Redis rate counters increase by two entries; E2E-07 checks successful real local limiter; E2E-09 checks both real module flags; E2E-12 checks rate-only decision before crash.
- Fresh isolated Redis DB 0 may contain only `rrl:*` keys; no nonzero DB or other keys. This checks no unexpected reputation, blacklist, or login-accounting keys in this test fixture, not that every possible production write path is impossible.
- `manifest.json`, `summary.json`, per-case `response.headers.txt`, `gateway.log`, `backend.log`, `redis-state.json`, and baseline/recovery profile evidence. Per-case `gateway-fault-lab.conf` is a test-only configuration; never deploy it. No real secrets in generated evidence.
- Exit 0 only when 13/13 PASS and cleanup reports no failures. A failure keeps evidence and leaves acceptance OPEN. Send summary, console log, and relevant failing case folder for review. Do not commit generated evidence directories or logs as source. Review source files, update the main plan and acceptance record separately; Jenkins execution remains FI-09 pending until real CI logs exist.

## Known remaining scope

This is runtime enforcement with a mock backend, not production TLS validation, Django authentication, a full Redis outage, or a benchmark. Required module *exceptions* and the two rate modules' known silent errors are covered; other silent failures (e.g. blacklist's uncached Redis read degradation) need an explicit route-level availability policy if production requires fail-closed on those events. This harness intentionally does not make new production policy choices. The real Redis integration suite from P0.5.3 should also be repeated on final source before full P0.5 acceptance if not already done.
