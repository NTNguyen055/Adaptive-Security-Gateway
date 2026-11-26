-- P0.5.4: centralized exception policy for trusted Gateway module calls.
-- No Redis writes, blacklist mutations, ngx.exit, or Telegram calls.
-- Keep module failures separate from malicious-client evidence.
-- LuaJIT / Lua 5.1 compatible.
local M = {}
local module_names

local REQUIRED = {
    xff_guard = true,
    ip_blacklist = true,
    geo_block = true,
    waf_sqli_xss = true,
    jwt_auth = true,
}
local OPTIONAL = {
    bad_bot = true,
    rate_limit = true,
    rate_limit_redis = true,
}

function M.register(trusted_map)
    assert(type(trusted_map) == "table", "trusted module map required")
    local names = {}
    for module, name in pairs(trusted_map) do
        assert(type(module) == "table" and type(module.run) == "function",
            "trusted module must expose run()")
        assert(type(name) == "string" and (REQUIRED[name] or OPTIONAL[name]),
            "unknown module policy classification")
        names[module] = name
    end
    module_names = names
end

local function valid_security(ctx)
    return type(ctx) == "table" and type(ctx.security) == "table"
end

local function prior_denial(ctx)
    if not valid_security(ctx) then return nil end
    local s = ctx.security
    -- Do not let a rate-only flag downgrade an independently established block.
    if s.risk_action == "block" then return 403 end
    if s.block == true then
        if s.rate_only_limited == true and s.risk_action == "limit"
            and not (s.waf_sqli or s.waf_xss or s.ip_blacklisted
                 or s.jwt_missing or s.jwt_invalid or s.xff_chain_abuse
                 or s.geo_blocked) then
            return 429
        end
        return 403
    end
    return nil
end

local function log_failure(scope, name, err)
    -- Logs are internal only. Never place exception strings into HTTP responses.
    pcall(ngx.log, ngx.ERR,
        "[GATEWAY][FAULT][", scope, "] module=", tostring(name),
        " error=", tostring(err))
end

local function mark_fault(ctx, name)
    if not valid_security(ctx) then return end
    local s = ctx.security
    s.gateway_degraded = true
    if not s.gateway_faults then s.gateway_faults = {} end
    s.gateway_faults[name] = true
end

-- Execute the *existing* shadow wrapper; never re-run a module after exception
-- because it may already have performed side effects before throwing.
-- Returns nil when pipeline may continue, otherwise terminal HTTP status.
function M.run_module(module, ctx, shadow)
    local name = module_names and module_names[module]
    if not name or not valid_security(ctx)
        or type(shadow) ~= "table" or type(shadow.run) ~= "function" then
        log_failure("module", name or "unregistered", "invalid_gateway_contract")
        return prior_denial(ctx) or 503
    end

    -- shadow.run returns the protected module's pcall tuple.
    -- Protect the shadow wrapper itself against instrumentation exceptions.
    local wrapper_ok, module_ok, err = pcall(shadow.run, module, ctx)
    if wrapper_ok and module_ok == true then return nil end
    local reason = wrapper_ok and err or module_ok
    log_failure("module", name, reason)
    mark_fault(ctx, name)

    local denied = prior_denial(ctx)
    if denied then return denied end
    if REQUIRED[name] then return 503 end
    return nil  -- Optional control failed; other controls remain active.
end

-- Evaluate availability of both rate-limiting layers.
-- Operational failures must not become malicious-IP evidence.
function M.after_modules(ctx)
    if not valid_security(ctx) then
        return 503
    end

    local s = ctx.security
    local faults = s.gateway_faults or {}

    -- L1: OpenResty local rate limiter.
    local local_unavailable =
        faults.rate_limit == true
        or s.local_rl_error == true

    -- L2: Redis sliding-window rate limiter.
    local redis_unavailable =
        faults.rate_limit_redis == true
        or s.redis_rl_fail == true
        or s.redis_rl_error == true

    -- Both L1 and L2 are unavailable.
    if local_unavailable and redis_unavailable then
        log_failure(
            "rate",
            "both_rate_limit_layers",
            "unavailable"
        )

        -- Preserve an established security denial.
        return prior_denial(ctx) or 503
    end

    return nil
end

-- Risk scoring fails safely, preserving a previously established request deny.
-- Treat a crash as service degradation; never infer client maliciousness.
function M.run_risk(ctx, engine)
    if not valid_security(ctx) or type(engine) ~= "table"
        or type(engine.run) ~= "function" then
        log_failure("risk", "risk_engine", "invalid_gateway_contract")
        return prior_denial(ctx) or 503
    end
    local ok, err = pcall(engine.run, ctx)
    if ok then return nil end
    log_failure("risk", "risk_engine", err)
    mark_fault(ctx, "risk_engine")
    return prior_denial(ctx) or 503
end

-- Drop-in replacement for the existing module loop + risk_engine pcall.
-- ngx.exit remains in the caller, so this module is also unit-testable.
function M.run_pipeline(ctx, modules, shadow, engine)
    if not valid_security(ctx) or type(modules) ~= "table" then
        log_failure("pipeline", "modules", "invalid_gateway_contract")
        return prior_denial(ctx) or 503
    end
    for _, module in ipairs(modules) do
        if ctx.security.block == true then break end
        local status = M.run_module(module, ctx, shadow)
        if status then return status end
    end
    local degraded_status = M.after_modules(ctx)
    if degraded_status then return degraded_status end
    return M.run_risk(ctx, engine)
end

return M
