-- P0.2.4-A2: in-process normalizer for existing OpenResty security modules.
-- PASSIVE / SHADOW ONLY. Do not use this module to replace live enforcement yet.
-- No ngx, Redis, HTTP, network, or global state. LuaJIT / Lua 5.1 compatible.
-- Capture a detector's output immediately after its protected pcall returns;
-- never infer provenance from client headers or unobserved final ctx.signals.
local policy = require "security_policy"
local M = {}

local SPECS = {
    waf_sqli_xss = {waf_sqli="waf_sqli", waf_xss="waf_xss"},
    bad_bot = {
        bad_bot_scanner="bad_bot_scanner", bad_bot_headless="bad_bot_headless",
        empty_ua="empty_ua", ua_unknown="ua_unknown", dev_tool="dev_tool",
    },
    xff_guard = {
        xff_chain_abuse="xff_chain_abuse", xff_spoof="xff_spoof",
        xff_malformed="xff_malformed", xff_private_chain="xff_private_chain",
    },
    geo_block = {geo_blocked="geo_block", geo_unknown="geo_unknown"},
    jwt_auth = {
        jwt_missing="jwt_missing", jwt_malformed="jwt_malformed",
        jwt_invalid="jwt_invalid", jwt_alg_attack="jwt_alg_attack",
        jwt_payload_invalid="jwt_payload_invalid", jwt_no_exp="jwt_no_exp",
        jwt_expired="jwt_expired", jwt_nbf="jwt_nbf",
        jwt_iat_future="jwt_iat_future", jwt_replay="jwt_replay",
    },
    rate_limit = {rate_limit_hard="rate_limit_hard", rate_limit_burst="rate_limit_burst"},
    rate_limit_redis = {
        redis_rate_exceeded="redis_rate_exceeded", redis_rate_warn="redis_rate_warn",
    },
    ip_blacklist = {ip_blacklisted="ip_blacklist_cached"},
    brute_force_login = {brute_force_attack="brute_force_attack"},
    -- Future producers MUST be instrumented and tested before use.
    login_accounting = {auth_account_backoff="auth_account_backoff"},
    ml_detector = {ml_anomaly="ml_anomaly"},
}
local ALIASES = {
    ip_blacklist = {
        ip_blacklist_manual=true, ip_blacklist_auto=true,
        ip_blacklist_cached=true,
    },
    jwt_auth = {jwt_blocked_cache=true, jwt_ip_changed=true},
}
local MAX_RAW_SIGNALS = 128
local ALL_KNOWN = {}
for _, flags in pairs(SPECS) do
    for _, id in pairs(flags) do ALL_KNOWN[id] = true end
end
for _, aliases in pairs(ALIASES) do
    for id in pairs(aliases) do ALL_KNOWN[id] = true end
end

local function array_size(value)
    if value == nil then return 0 end
    if type(value) ~= "table" then return nil end
    local count, max_index = 0, 0
    for index in pairs(value) do
        if type(index) ~= "number" or index < 1 or index % 1 ~= 0 then
            return nil
        end
        count = count + 1
        if count > MAX_RAW_SIGNALS then return nil end
        if index > max_index then max_index = index end
    end
    if count ~= max_index then return nil end
    return count
end

local function source_event(trace, id, source)
    if trace.present[id] then return end
    trace.present[id] = true
    trace.signals[#trace.signals + 1] = {id=id, source=source}
end

local function mark_error(trace, module, code)
    trace.errors[#trace.errors + 1] = {module=module, code=code}
end

-- trusted opts must be constructed by nginx.conf, NEVER by client input.
-- jwt_required: whether the route really uses JWT (NOT all Django session routes).
-- required_modules: e.g. {jwt_auth=true}. Missing/skipped required modules fail closed.
function M.new(opts)
    if type(opts) ~= "table" or type(opts.jwt_required) ~= "boolean" then
        return nil, "invalid_route_config"
    end
    -- Exact legacy branches differ by Nginx location.
    -- "standard": /, /admin/, /doLogin/
    -- "login": /login/ (does not implement rate-only override)
    -- "assets": /static/, /media/ (no explicit 429 action)
    local route_mode = opts.route_mode or "standard"
    if route_mode ~= "standard" and route_mode ~= "login"
        and route_mode ~= "assets" then
        return nil, "invalid_route_mode"
    end
    local required = opts.required_modules or {}
    if type(required) ~= "table" then return nil, "invalid_required_modules" end
    for name, enabled in pairs(required) do
        if not SPECS[name] or enabled ~= true then
            return nil, "invalid_required_module"
        end
    end
    return {
        jwt_required = opts.jwt_required,
        route_mode = route_mode,
        required = required,
        seen = {}, signals = {}, present = {}, errors = {},
        detector_blocked = false, -- non-rate detector block ONLY
        ban_origin = nil, jwt_status = nil,
        required_control_failed = false,
        pending = nil,
    }
end

function M.begin_step(trace, module, ctx)
    if type(trace) ~= "table" or type(ctx) ~= "table"
        or type(ctx.security) ~= "table" or not SPECS[module] then
        return nil, "invalid_observation"
    end
    if trace.pending or trace.seen[module] then
        return nil, "duplicate_or_nested_module"
    end
    local count = array_size(ctx.security.signals)
    if not count then return nil, "invalid_legacy_signals" end
    local previous = {}
    for flag in pairs(SPECS[module]) do
        previous[flag] = ctx.security[flag] == true
    end
    local step = {
        module=module, previous=previous, signal_count=count,
        block_before=ctx.security.block == true,
    }
    trace.pending = step
    return step
end

-- successful MUST be the actual pcall status; do not mark failures as success.
function M.end_step(trace, step, ctx, successful)
    if type(trace) ~= "table" or trace.pending ~= step
        or type(step) ~= "table" or type(ctx) ~= "table"
        or type(ctx.security) ~= "table" or type(successful) ~= "boolean" then
        return nil, "invalid_observation_end"
    end
    trace.pending = nil
    local module = step.module
    trace.seen[module] = true
    if not successful then
        -- A crashing module may already have set block=true before raising.
        -- Never silently convert that partial deny to an allow verdict.
        if ctx.security.block == true
            and not step.block_before
            and module ~= "rate_limit" and module ~= "rate_limit_redis" then
            trace.detector_blocked = true
        end
        mark_error(trace, module, "module_crash")
        if trace.required[module] then trace.required_control_failed = true end
        return true
    end

    local security = ctx.security
    local count = array_size(security.signals)
    if not count or count < step.signal_count then
        mark_error(trace, module, "invalid_legacy_signals")
        trace.required_control_failed = true
        return true
    end

    -- Attribute ONLY values appended during this specific module execution.
    -- An existing signal from an earlier module cannot be reassigned to this one.
    for i = step.signal_count + 1, count do
        local raw = security.signals[i]
        if type(raw) ~= "string" then
            mark_error(trace, module, "malformed_signal")
            trace.required_control_failed = true
        else
            -- Lua patterns do not support quantified capturing groups.
            local id = raw:match("^([a-z][a-z0-9_]*)")
            local suffix = id and raw:sub(#id + 1) or nil
            if id and #raw <= 256 and (suffix == "" or suffix:sub(1, 1) == ":") then
                local flags = SPECS[module]
                local known = ALIASES[module] and ALIASES[module][id]
                for _, expected in pairs(flags) do
                    if expected == id then known = true; break end
                end
                if known then
                    source_event(trace, id, module)
                    if module == "ip_blacklist" and security.ip_blacklisted == true then
                        local new_origin = nil
                        if id == "ip_blacklist_manual" then new_origin = "manual" end
                        if id == "ip_blacklist_auto" then new_origin = "automatic" end
                        if new_origin and security.block ~= true then
                            mark_error(trace, module, "ban_without_block")
                            trace.required_control_failed = true
                        elseif new_origin and trace.ban_origin and trace.ban_origin ~= new_origin then
                            mark_error(trace, module, "conflicting_ban_origin")
                            trace.required_control_failed = true
                        elseif new_origin then
                            trace.ban_origin = new_origin
                        end
                    end
                else
                    -- Unknown output is ignored, not promoted to a trusted source.
                    mark_error(trace, module, "unrecognized_signal")
                    if ALL_KNOWN[id] then
                        -- A known security signal claimed by the wrong module
                        -- is a protocol violation, not benign telemetry.
                        trace.required_control_failed = true
                    end
                end
            else
                mark_error(trace, module, "malformed_signal")
                trace.required_control_failed = true
            end
        end
    end

    -- Some legacy modules only set flags, without a corresponding signal.
    for flag, id in pairs(SPECS[module]) do
        if security[flag] == true and not step.previous[flag] then
            -- IP blacklist origin cannot be proved from ip_blacklisted alone.
            if module ~= "ip_blacklist" then source_event(trace, id, module) end
        end
    end
    if security.block == true and not step.block_before
        and module ~= "rate_limit" and module ~= "rate_limit_redis" then
        trace.detector_blocked = true
    end

    if module == "jwt_auth" then
        if security.jwt_config_error == true then
            trace.jwt_status = "error"
            trace.required_control_failed = true
        elseif trace.present.jwt_replay or trace.present.jwt_ip_changed then
            trace.jwt_status = "ip_changed"
        elseif trace.present.jwt_missing then
            trace.jwt_status = "missing"
        elseif trace.present.jwt_invalid or trace.present.jwt_malformed
            or trace.present.jwt_alg_attack or trace.present.jwt_blocked_cache
            or trace.present.jwt_payload_invalid or trace.present.jwt_no_exp
            or trace.present.jwt_expired or trace.present.jwt_nbf
            or trace.present.jwt_iat_future then
            trace.jwt_status = "invalid"
        elseif security.jwt_valid == true then
            trace.jwt_status = "verified"
        end
    end
    return true
end

local function legacy_action(security, mode)
    local action = security.risk_action
    if mode == "assets" then
        if security.block == true or action == "block" then
            return "BLOCK_REQUEST", 403
        end
        return "ALLOW", nil
    end
    if mode == "standard" and security.rate_only_limited == true
        and action == "limit" then
        return "THROTTLE", 429
    end
    if security.block == true or action == "block" then
        return "BLOCK_REQUEST", 403
    end
    if action == "limit" then return "THROTTLE", 429 end
    return "ALLOW", nil
end

-- Call after modules and risk_engine to produce a compare-only report.
-- No live response/header/Redis/blacklist writes occur here.
function M.finish(trace, ctx)
    if type(trace) ~= "table" or type(ctx) ~= "table"
        or type(ctx.security) ~= "table" or trace.pending then
        return nil, "invalid_report_state"
    end
    for module in pairs(trace.required) do
        if not trace.seen[module] then
            trace.required_control_failed = true
            mark_error(trace, module, "required_module_not_run")
        end
    end
    local security = ctx.security
    local ip_ban = nil
    if trace.ban_origin then
        ip_ban = {active=true, verified=true, origin=trace.ban_origin}
    end
    local score = security.risk_final
    if score == nil then score = security.risk end
    local input = {
        signals=trace.signals,
        required_control_failed=trace.required_control_failed,
        jwt_required=trace.jwt_required,
        jwt_status=trace.jwt_status,
        ip_ban=ip_ban,
        -- No account signal exists at Gateway before NAT-aware V3 integration.
        account_restricted=trace.present.auth_account_backoff == true,
        risk_score=score,
        legacy_blocked=trace.detector_blocked,
        legacy_rate_only=security.rate_only_limited == true,
    }
    local result, err = policy.evaluate(input)
    if not result then return nil, err end
    local old_action, old_status = legacy_action(security, trace.route_mode)
    return {
        policy=result,
        legacy_action=old_action,
        legacy_status=old_status,
        status_diff=(result.http_status ~= old_status),
        errors=trace.errors,
        signals=trace.signals,
        input=input,
    }
end

return M
