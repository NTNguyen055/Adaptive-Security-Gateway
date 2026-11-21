# Security Correlator (Shadow Contract)

**Checkpoint base:** `263ea9e` (`feature/p0-security-baseline`)  
**Status:** source/tests prepared; integration and Docker acceptance pending.  
**Scope:** real in-process WAF event aggregation **without automatic IP-ban issuance**.

## 1. Responsibilities and trust boundary

- Observations are supplied only by `security_shadow.log()` using the server-side `security_signal_adapter` trace.
- The only counted events are **WAF** `waf_sqli` and `waf_xss`, attributed to `waf_sqli_xss`. Other detector signals, raw risk scores and request/client headers are not independent exploit proof.
- The peer identity is `ngx.var.remote_addr`; `ngx.var.request_id` is used to deduplicate HTTP requests.
- State lives in the dedicated `ngx.shared.security_correlator_cache` dictionary. Each key expires after at most 360 seconds. No traffic, IPs, payloads, passwords or emails are written into the correlator log.
- A candidate appears as `SUSPICIOUS_SHADOW` only with at least **8 WAF-observed requests**, **3 distinct 60-second buckets**, and **2 WAF classes** within the five most recent buckets. It is explicitly **not** a confirmation of exploit success, independent detectors or low NAT collateral risk.
- The correlator cannot emit an approved IP-ban candidate: `verify()` returns `nil, "independent_evidence_and_nat_assessment_unavailable"` irrespective of input.

## 2. Why `verify()` stays closed

`ip_ban_authorizer.lua` requires all of the following:

1. Server-verified *confirmed* exploit events, not merely WAF signatures.
2. Independently verified sources of evidence, not two labels from a single WAF module.
3. At least 8 events, 3 windows, 2 attack classes and 120 seconds of proven event span.
4. A reliable `low_collateral_verified` finding and `shared_ip_observed == false`; absent evidence is **unknown**, not safe.

At present the repository has no trustworthy independent exploit verifier or NAT-assessment producer. Releasing a ban under these conditions would be unsafe for CGNAT/shared-IP users. The shadow correlator remains a research instrument until these prerequisites exist. This is a deliberate security boundary, not an implicit guarantee of safe automatic blocking.

## 3. Existing-file integration required (manual edits)

### `nginx/nginx.conf`

Under `# ================= ENV DECLARATIONS =================`, below `env SECURITY_SHADOW_LOG_ALL;`, add:

```nginx
env SECURITY_CORRELATOR_SHADOW_ENABLED;
```

Under `# ================= SHARED MEMORY =================`, below `lua_shared_dict brute_force_cache    5m;`, add:

```nginx
lua_shared_dict security_correlator_cache 5m;
```

**Reason:** Preserve the explicit rollout flag and isolate correlator counters from blacklist/rate-limit caches.

### `nginx/lua/security_shadow.lua`

Directly after `local adapter = require "security_signal_adapter"`, add:

```lua
local correlator = require "security_correlator"
```

In `M.log()`, immediately after the following success guard:

```lua
local report, problem = adapter.finish(state.trace, state.ctx)
if not report then
    log_error("adapter_finish_failed: " .. tostring(problem))
    return
end
```

insert:

```lua
        if (os.getenv("SECURITY_CORRELATOR_SHADOW_ENABLED") or "false"):lower() == "true" then
            local call_ok, summary, correlation_err = pcall(correlator.observe, {
                trace = state.trace,
                peer_ip = ngx.var.remote_addr,
                request_id = ngx.var.request_id,
                partial = skipped_required
                    or state.instrumentation_error ~= nil
                    or state.trace.required_control_failed == true
                    or #report.errors > 0,
            })

            if not call_ok then
                log_error("correlator_crashed")
            elseif not summary then
                log_error("correlator_error: " .. tostring(correlation_err))
            elseif summary.notify then
                ngx.log(
                    ngx.WARN,
                    "[SECURITY_CORRELATOR] status=SUSPICIOUS_SHADOW",
                    " events=", summary.event_count,
                    " windows=", summary.distinct_windows,
                    " classes=", summary.distinct_attack_classes,
                    " automatic_ban=disabled"
                )
            end
        end
```

**Reason:** Bind accounting to the server-attributed trace *before* the existing report suppression/early return, without changing any HTTP enforcement or Redis ban state.

### `nginx/tests/test_ip_ban_issuer.lua`

Find the existing `test('No trusted correlator means zero issuance'...)` case. Replace only this case:

```lua
test('Installed shadow correlator rejects unverified incidents', function()
    local result, err = writer.issue_verified({approved = true})
    assert(result == nil and err == 'correlation_not_verified')
    assert(state.connections == 0 and #state.evals == 0)
end)
```

**Reason:** The module now exists; failure to authorize becomes `correlation_not_verified`, rather than `trusted_correlator_unavailable`.

### `nginx/lua/ip_ban_issuer.lua`

Update **comments only**, not functional logic. Replace claims saying the correlator module "does not exist" with "the installed correlator is shadow-only and refuses unverified issuance".

### `tests/run-unit.sh`

In `gateway_suite()`'s `local pairs=(` list, immediately below `'test_ip_ban_issuer:ip_ban_issuer'`, add:

```bash
    'test_security_correlator:security_correlator'
```

**Reason:** Ensure future Gateway offline regressions include correlator behavior.

## 4. Acceptance workflow (local only)

**Keep** `LOGIN_ACCOUNTING_ENABLED=False` by default; it is unrelated to the correlator shadow flag.

```bash
bash tests/run-unit.sh gateway

docker compose --env-file .env.local \
  -f docker-compose.dev.yml build gateway

docker compose --env-file .env.local \
  -f docker-compose.dev.yml \
  run --rm --no-deps --entrypoint openresty gateway -t

docker compose --env-file .env.local \
  -f docker-compose.dev.yml \
  up -d --no-deps --force-recreate --wait gateway

bash nginx/tests/test_authorized_ban_live.sh
bash nginx/tests/test_blacklist_http_live.sh
bash nginx/tests/test_reputation_cas_live.sh
```

With the previous 122 cases unchanged, adding 23 correlator tests gives an **expected** total of 145 LuaJIT tests across 13 suites. This is a projection, not a result observed on the user's Docker stack.

For a bounded local-only shadow trial, set **both** `SECURITY_SHADOW_ENABLED=true` and `SECURITY_CORRELATOR_SHADOW_ENABLED=true` in `.env.local` (untracked), recreate only gateway, and inspect server logs. Revert both values to the prior setting afterward and recreate gateway again. Do **not** enable automatic IP-ban issuance or change production environment.

## 5. Known limitations

- A WAF signature is a heuristic observation, not verified exploit execution. Correlating its events does not prove a confirmed campaign.
- `ngx.shared` keeps bounded ephemeral state; it is reset on gateway restart and may evict observations under capacity pressure.
- For large distributed attacks, per-IP tracking undercounts cross-IP campaigns; account-aware login is a separate signal channel.
- IPv4/IPv6 canonicalization is delegated to Nginx's peer address; no untrusted XFF is used.
- MD5 is used *only* to shorten an in-memory cache key, not as an authentication or integrity primitive.
- No long-retention forensic audit trail is produced by this module.
- `verify()` is intentionally fail-closed until independently sourced exploit proof and NAT provenance are available.

**Do not close P0.2 merely because shadow observations cross a threshold.** Final acceptance also requires live regression, rollback validation and updated threat-model/test-matrix documentation.
