-- Mock regression tests for rate-only Risk Engine mitigation.
-- Usage: luajit test_rate_only_guard.lua /tmp/risk_engine_under_test.lua
-- No real Redis, HTTP traffic or Telegram calls.

local source = (arg and arg[1]) or "nginx/lua/risk_engine.lua"
local state = { redis_calls = 0, writes = {}, kv = {}, alerts = {} }
local ip = "192.0.2.10"
ngx = {
    ERR = 3, WARN = 4, INFO = 6, null = {},
    var = { realip_remote_addr = ip, remote_addr = ip },
    log = function(...) end,
}
local red = {}
function red:get(key)
    return state.kv[key] or ngx.null
end
function red:set(key, val, ...)
    state.kv[key] = val
    state.writes[#state.writes + 1] = "set:" .. key
    return "OK"
end
function red:sadd(key, val)
    state.writes[#state.writes + 1] = "sadd:" .. key
    return 1
end

-- Simulate the atomic EVAL contract; commit none when it fails.
function red:eval(script, nkeys, score_key, stamp_key, ban_key, bf_key, score, ttl, stamp, has_stamp, has_ban, ban_ttl)
    assert(type(script)=="string" and nkeys==4 and score_key:match("^risk:v1:"), "bad EVAL contract")
    if tonumber(has_stamp)==1 then self:set(stamp_key, stamp, "EX", ttl) end
    self:set(score_key, score, "EX", ttl)
    if tonumber(has_ban)==1 then self:set(ban_key, "1", "EX", ban_ttl) end
    return 1
end

package.loaded["redis_helper"] = {
    get_redis = function(db)
        assert(db == 0)
        state.redis_calls = state.redis_calls + 1
        return red
    end,
    close = function(_) end,
}
package.loaded["telegram_alert"] = {
    send = function(payload)
        state.alerts[#state.alerts + 1] = payload
    end,
}
metric_blocked = nil
local module = assert(loadfile(source))()
assert(type(module.run) == "function")

local function reset()
    state.redis_calls, state.writes, state.kv, state.alerts = 0, {}, {}, {}
    ngx.var = { realip_remote_addr = ip, remote_addr = ip }
end
local function check(v, msg)
    if not v then error(msg, 2) end
end
local function fresh(fields, signals, risk)
    local security = { client_ip = ip, risk = risk or 0,
                       signals = signals or {}, block = true }
    for k, v in pairs(fields) do security[k] = v end
    return { security = security }
end
local function no_redis()
    check(state.redis_calls == 0, "unexpected Redis connection")
    check(#state.writes == 0, "unexpected reputation/blacklist writes")
    check(#state.alerts == 0, "unexpected alert")
end
local passed, failed = 0, 0
local function case(name, fn)
    reset()
    local ok, err = pcall(fn)
    if ok then
        passed = passed + 1
        print("PASS  " .. name)
    else
        failed = failed + 1
        print("FAIL  " .. name .. ": " .. tostring(err))
    end
end
local function expect_rate_only(ctx)
    module.run(ctx)
    check(ctx.security.block == true, "request not blocked")
    check(ctx.security.rate_only_limited == true, "rate-only marker missing")
    check(ctx.security.risk_action == "limit", "expected limit action")
    check(ngx.var.log_security_block == "limit", "expected limit in security log")
    no_redis()
end

case("hard rate rejection does not blacklist or write reputation", function()
    expect_rate_only(fresh({rate_limit_hard = true}, {"rate_limit_hard"}, 10))
end)
case("burst rate rejection does not blacklist or write reputation", function()
    expect_rate_only(fresh({rate_limit_burst = true}, {"rate_limit_burst"}, 10))
end)
case("Redis rate exceeded does not blacklist or write reputation", function()
    expect_rate_only(fresh({redis_rate_exceeded = true}, {"redis_rate_exceeded"}, 10))
end)
case("repeated rate-only requests never write reputation", function()
    for _ = 1, 8 do
        expect_rate_only(fresh({rate_limit_hard = true}, {"rate_limit_hard"}, 10))
    end
end)
case("missing JWT plus rate-only still avoids IP punishment", function()
    expect_rate_only(fresh({jwt_missing = true, rate_limit_hard = true},
                           {"jwt_missing", "rate_limit_hard"}, 10))
end)
case("confirmed WAF SQLi is not bypassed by rate-only guard", function()
    local ctx = fresh({rate_limit_hard = true, waf_sqli = true},
                      {"rate_limit_hard", "waf_sqli"}, 80)
    module.run(ctx)
    check(ctx.security.block == true, "WAF block lost")
    check(ctx.security.risk_action == "block", "WAF action lost")
    check(state.redis_calls > 0, "strong WAF evidence should reach reputation handling")
    check(state.kv["risk:v1:" .. ip] ~= nil, "WAF reputation not written")
    check(state.kv["blacklist:" .. ip] ~= nil, "WAF blacklist behavior unexpectedly removed")
end)
case("context-only signals remain non-punitive", function()
    local ctx = {security = {client_ip = ip, risk = 40, signals = {"xff_private_client"}}}
    module.run(ctx)
    check(ctx.security.risk_action == "pass", "context request should pass")
    no_redis()
end)

print(string.format("Rate-only guard mock tests: %d passed, %d failed, %d total",
    passed, failed, passed + failed))
if failed > 0 then os.exit(1) end
