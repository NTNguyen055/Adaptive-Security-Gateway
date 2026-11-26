-- P0.5.4 isolated fault-injection contract tests.
-- Usage: luajit test_gateway_fault_guard.lua path/to/gateway_fault_guard.lua
local source = (arg and arg[1]) or "nginx/lua/gateway_fault_guard.lua"
local chunk, load_error = loadfile(source)
assert(chunk, load_error)

local logs = {}
_G.ngx = {
    ERR = 3,
    log = function(...)
        logs[#logs + 1] = table.concat((function(...)
            local v = {...}
            for i = 1, #v do v[i] = tostring(v[i]) end
            return v
        end)(...), "")
    end,
}

local guard = chunk()
local modules = {}

local function mod(name, f)
    local m = {run = f or function() end}
    modules[m] = name
    return m
end

local xff = mod("xff_guard")
local blacklist = mod("ip_blacklist")
local geo = mod("geo_block")
local waf = mod("waf_sqli_xss")
local jwt = mod("jwt_auth")
local bot = mod("bad_bot")
local local_rate = mod("rate_limit")
local redis_rate = mod("rate_limit_redis")

guard.register(modules)

local function ctx(fields)
    local s = {risk = 0, signals = {}}
    for k, v in pairs(fields or {}) do s[k] = v end
    return {security = s}
end

local shadow = {run = function(module, request)
    return pcall(module.run, request)
end}

local function failing_shadow(message)
    return {run = function() error(message or "injected module crash") end}
end

local function module_crash_shadow(message)
    return {run = function(module, request)
        return pcall(function() error(message or "module_exception") end)
    end}
end

local passed, failed = 0, 0
local function check(value, why)
    if not value then error(why, 2) end
end

local function case(label, fn)
    logs = {}
    local ok, err = pcall(fn)
    if ok then
        passed = passed + 1
        print("PASS  " .. label)
    else
        failed = failed + 1
        print("FAIL  " .. label .. ": " .. tostring(err))
    end
end

local function expect_required(m)
    local request = ctx()
    local status = guard.run_module(m, request, failing_shadow())
    check(status == 503, "mandatory control failure did not return 503")
    check(request.security.gateway_degraded == true, "degradation not recorded")
    check(request.security.gateway_faults[modules[m]], "fault type missing")
    check(request.security.risk == 0 and #request.security.signals == 0,
        "infrastructure failure created attack evidence")
end

case("clean mandatory module does not alter response", function()
    local request = ctx()
    check(guard.run_module(xff, request, shadow) == nil, "clean call failed")
    check(request.security.gateway_faults == nil, "clean call allocated fault state")
end)

case("XFF guard crash fails closed", function() expect_required(xff) end)
case("IP blacklist crash fails closed", function() expect_required(blacklist) end)
case("Geo policy crash fails closed", function() expect_required(geo) end)
case("WAF crash fails closed", function() expect_required(waf) end)
case("JWT authentication crash fails closed", function() expect_required(jwt) end)
case("Optional bot crash remains degraded not malicious", function()
    local request = ctx()
    check(guard.run_module(bot, request, failing_shadow()) == nil,
        "optional bot crash should not cause global outage")
    check(request.security.gateway_degraded and request.security.gateway_faults.bad_bot,
        "bot fault not visible")
    check(request.security.block ~= true and request.security.risk == 0,
        "bot crash incorrectly punished client")
end)

case("Local rate limiter crash relies on Redis fallback", function()
    local request = ctx()
    check(guard.run_module(local_rate, request, failing_shadow()) == nil,
        "local rate failure should allow second layer")
    check(guard.after_modules(request) == nil, "healthy Redis fallback was rejected")
end)

case("Redis limiter crash relies on local fallback", function()
    local request = ctx()
    check(guard.run_module(redis_rate, request, failing_shadow()) == nil,
        "Redis rate failure should allow first layer")
    check(guard.after_modules(request) == nil, "healthy local fallback rejected")
end)

case("Both rate limiter modules crashing returns 503", function()
    local request = ctx()
    guard.run_module(local_rate, request, failing_shadow())
    guard.run_module(redis_rate, request, failing_shadow())
    check(guard.after_modules(request) == 503, "both failures did not fail closed")
end)

case("Local rate crash plus Redis degraded flag returns 503", function()
    local request = ctx({redis_rl_fail = true})
    guard.run_module(local_rate, request, failing_shadow())
    check(guard.after_modules(request) == 503, "dual degradation not caught")
end)

case("Local rate crash plus Redis error returns 503", function()
    local request = ctx({redis_rl_error = true})
    guard.run_module(local_rate, request, failing_shadow())
    check(guard.after_modules(request) == 503, "Redis error was ignored")
end)

-- Silent local limiter failure handling.
case("Silent local limiter error plus Redis outage returns 503", function()
    local request = ctx({
        local_rl_error = true,
        redis_rl_fail = true
    })

    check(
        guard.after_modules(request) == 503,
        "dual silent degradation was not rejected"
    )

    check(
        request.security.risk == 0,
        "infrastructure failure increased risk"
    )
end)

case("Silent local limiter error plus Redis pipeline error returns 503", function()
    local request = ctx({
        local_rl_error = true,
        redis_rl_error = true
    })

    check(
        guard.after_modules(request) == 503,
        "dual operational error was not rejected"
    )

    check(
        request.security.block ~= true,
        "operational failure must not mark client malicious"
    )
end)

case("Silent local limiter error with healthy Redis may continue", function()
    local request = ctx({
        local_rl_error = true
    })

    check(
        guard.after_modules(request) == nil,
        "healthy Redis fallback was rejected"
    )

    check(
        request.security.block ~= true,
        "single-layer degradation must not punish client"
    )
end)

case("Redis degradation alone is not a malicious indicator", function()
    local request = ctx({redis_rl_fail = true})
    check(guard.after_modules(request) == nil, "functional local limiter was ignored")
    check(request.security.block == nil and request.security.risk == 0,
        "Redis infrastructure fault punished IP")
end)

case("Unknown security module cannot bypass mandatory classification", function()
    local request = ctx()
    check(guard.run_module({run=function() end}, request, shadow) == 503,
        "unregistered module was permitted")
end)

case("Shadow wrapper failure for required control returns 503", function()
    expect_required(blacklist)
end)

case("Protected module returned pcall false rather than wrapper exception", function()
    local request = ctx()
    check(guard.run_module(jwt, request, module_crash_shadow()) == 503,
        "unhandled protected module failure")
end)

case("Pre-existing hard block is not downgraded after module crash", function()
    local request = ctx({block = true, waf_sqli = true, risk_action = "block"})
    check(guard.run_module(blacklist, request, failing_shadow()) == 403,
        "hard block was downgraded")
    check(request.security.block == true, "upstream block was cleared")
end)

case("Rate-only 429 is preserved on optional module crash", function()
    local request = ctx({block = true, rate_only_limited = true, risk_action = "limit"})
    check(guard.run_module(bot, request, failing_shadow()) == 429,
        "confirmed rate-only decision was lost")
end)

case("WAF block has priority over forged rate-only marker", function()
    local request = ctx({block = true, rate_only_limited = true,
        risk_action = "limit", waf_sqli = true})
    check(guard.run_module(bot, request, failing_shadow()) == 403,
        "WAF block downgraded to 429")
end)

case("Clean request risk engine crash fails closed", function()
    local request = ctx()
    local status = guard.run_risk(request, {run = function() error("mock risk crash") end})
    check(status == 503, "risk engine exception silently bypassed")
    check(request.security.gateway_faults.risk_engine, "risk exception not recorded")
end)

case("Risk crash preserves upstream hard block", function()
    local request = ctx({block = true, waf_xss = true})
    check(guard.run_risk(request, {run = function() error("boom") end}) == 403,
        "risk crash downgraded 403")
end)

case("Risk crash preserves established rate-only decision", function()
    local request = ctx({block = true, rate_only_limited = true, risk_action = "limit"})
    check(guard.run_risk(request, {run = function() error("boom") end}) == 429,
        "risk crash lost 429")
end)

case("Healthy risk run remains transparent", function()
    local request = ctx()
    check(guard.run_risk(request, {run = function(c) c.security.risk_action="pass" end}) == nil,
        "normal risk evaluation altered")
    check(request.security.risk_action == "pass", "risk output lost")
end)

-- P0.5.4 pipeline-level checks (integration of wrappers and decisions).
local critical = mod("ip_blacklist", function() error("blacklist crashed") end)
local soft = mod("bad_bot", function() error("bot crashed") end)
local local_fail = mod("rate_limit", function() error("local limiter crashed") end)
local redis_fail = mod("rate_limit_redis", function() error("redis limiter crashed") end)
local hard_block = mod("waf_sqli_xss", function(c)
    c.security.waf_sqli = true
    c.security.block = true
end)

local must_skip = mod("jwt_auth", function() error("short circuit failed") end)
guard.register(modules)
local good_risk = {run = function(c) c.security.risk_action = c.security.risk_action or "pass" end}

case("Pipeline clean route reaches risk evaluation", function()
    local request = ctx()
    check(guard.run_pipeline(request, {xff, blacklist, bot}, shadow, good_risk) == nil,
        "normal pipeline failed")
    check(request.security.risk_action == "pass", "risk engine not evaluated")
end)

case("Pipeline mandatory blacklist exception stops before risk", function()
    local request = ctx()
    local risk_called = false
    local status = guard.run_pipeline(request, {xff, critical, bot}, shadow,
        {run = function() risk_called = true end})
    check(status == 503 and not risk_called, "mandatory crash fell through")
end)

case("Pipeline optional bot crash degrades then continues", function()
    local request = ctx()
    check(guard.run_pipeline(request, {xff, soft}, shadow, good_risk) == nil,
        "optional fault created 503")
    check(request.security.gateway_degraded and request.security.risk_action == "pass",
        "degraded trace not retained")
end)

case("Pipeline dual limiter failure stops before Risk Engine", function()
    local request = ctx()
    local risk_called = false
    local status = guard.run_pipeline(request, {local_fail, redis_fail}, shadow,
        {run = function() risk_called = true end})
    check(status == 503 and not risk_called, "both failures were not caught")
end)

case("Pipeline upstream WAF block short circuits JWT", function()
    local request = ctx()
    check(guard.run_pipeline(request, {hard_block, must_skip}, shadow, good_risk) == nil,
        "WAF block mistakenly treated as module fault")
    check(request.security.block and request.security.waf_sqli,
        "prior WAF decision erased")
end)

case("Pipeline Risk Engine exception rejects a clean request", function()
    local request = ctx()
    local status = guard.run_pipeline(request, {xff}, shadow,
        {run = function() error("injected risk failure") end})
    check(status == 503, "Risk Engine failure was ignored")
end)

case("Pipeline rejects malformed module list", function()
    check(guard.run_pipeline(ctx(), nil, shadow, good_risk) == 503,
        "invalid module list passed")
end)

print(string.format("Gateway Fault Guard tests: %d passed, %d failed, %d total",
    passed, failed, passed + failed))
if failed > 0 then os.exit(1) end
