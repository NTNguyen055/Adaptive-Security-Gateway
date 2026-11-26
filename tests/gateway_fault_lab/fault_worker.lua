-- TEST ONLY. Inserted into a disposable copy of nginx.conf by run_lab.py.
-- No request header, query parameter or public endpoint controls the fault.
-- FAULT_LAB_CASE is a literal supplied by the runner; never installed in nginx/lua.
local scenario = FAULT_LAB_CASE
local function trigger(name)
    ngx.log(ngx.ERR, "FAULT_LAB_TRIGGER case=", scenario, " module=", name)
end

local function crash(module, name)
    module.run = function(ctx)
        trigger(name)
        error("FAULT_LAB_SYNTHETIC_" .. name)
    end
end

local function verify_real_local()
    local original = rate_limit.run
    rate_limit.run = function(ctx)
        original(ctx)
        assert(not ctx.security.local_rl_error, "FAULT LAB local fallback failed")
        assert(not ctx.security.block, "FAULT LAB local fallback blocked")
        ngx.log(ngx.ERR, "FAULT_LAB_L1_OK")
    end
end

if scenario == "E2E-02" then
    crash(ip_blacklist, "ip_blacklist")

elseif scenario == "E2E-03" then
    crash(waf, "waf_sqli_xss")

elseif scenario == "E2E-04" then
    crash(jwt_auth, "jwt_auth")

elseif scenario == "E2E-05" then
    crash(bad_bot, "bad_bot")

elseif scenario == "E2E-06" then
    crash(rate_limit, "rate_limit")

elseif scenario == "E2E-07" then
    verify_real_local()
    crash(rate_limit_redis, "rate_limit_redis")

elseif scenario == "E2E-08" then
    crash(rate_limit, "rate_limit")
    crash(rate_limit_redis, "rate_limit_redis")

elseif scenario == "E2E-09" then

    -- Force a non-throwing init failure in the actual L1 module.
    local limit = require "resty.limit.req"
    limit.new = function(...)
        trigger("local_init_nil")
        return nil, "FAULT_LAB_SYNTHETIC_LOCAL_INIT"
    end

    -- Call the actual L2 module with an unavailable Redis connection.
    -- Restore the dependency even if the module throws; only this one
    -- request is sent to this fresh, single-worker Gateway.
    local helper = require "redis_helper"
    local original = rate_limit_redis.run
    local get = helper.get_redis
    rate_limit_redis.run = function(ctx)
        helper.get_redis = function(...)
            trigger("redis_connect_nil")
            return nil, "FAULT_LAB_SYNTHETIC_REDIS_CONNECT"
        end

        local ok, err = pcall(original, ctx)
        helper.get_redis = get
        if not ok then error(err) end
        assert(ctx.security.redis_rl_fail == true, "FAULT LAB missing real L2 failure flag")
        assert(ctx.security.local_rl_error == true, "FAULT LAB missing real L1 failure flag")
        ngx.log(ngx.ERR, "FAULT_LAB_SILENT_FLAGS_OK")
    end

elseif scenario == "E2E-10" then
    crash(risk_engine, "risk_engine")

elseif scenario == "E2E-11" then

    -- Synthesize an established WAF request denial, not a real exploit.
    -- Risk Engine fails BEFORE doing any reputation I/O.
    waf.run = function(ctx)
        trigger("waf_denial")
        local s = ctx.security
        s.signals = s.signals or {}
        s.waf_sqli = true
        s.block = true
        table.insert(s.signals, "waf_sqli")
    end

    crash(risk_engine, "risk_engine")

elseif scenario == "E2E-12" then
    -- Make the real L1 module receive a normal limiter rejection.
    local limit = require "resty.limit.req"
    limit.new = function(...)
        return { incoming = function(...)
            trigger("local_rejection")
            return nil, "rejected"
        end }
    end

    local original = risk_engine.run
    risk_engine.run = function(ctx)
        -- Establish the real rate-only decision before the exception.
        original(ctx)
        local s = ctx.security
        assert(s.rate_only_limited == true and s.risk_action == "limit"
            and s.block == true, "FAULT LAB rate-only precondition failed")
        ngx.log(ngx.ERR, "FAULT_LAB_RATE_DECISION_OK")
        trigger("risk_engine")
        error("FAULT_LAB_SYNTHETIC_risk_engine_after_decision")
    end

elseif scenario == "E2E-14"
    or scenario == "E2E-15" then

    -- Verify conditional security JSON logging on asset routes.
    crash(ip_blacklist, "ip_blacklist")

elseif scenario == "E2E-16"
    or scenario == "E2E-17" then

    -- Simulate an unavailable Login Accounting health check.
    -- The actual Nginx prelogin enforcement remains unchanged.
    brute_force_login.check_prelogin = function(ctx)
        trigger("login_accounting_health")
        return nil, "FAULT_LAB_SYNTHETIC_ACCOUNTING_UNAVAILABLE"
    end

elseif scenario ~= "E2E-01"
    and scenario ~= "E2E-13" then

    error("FAULT LAB unsupported scenario")
end
