-- Stage 1.4 batch 1 regression: time-bounded risk reputation & auto-blocks.
-- Run: luajit test_risk_reputation_ttl.lua /tmp/risk_engine_under_test.lua
-- No real Redis or Telegram calls.
local source = (arg and arg[1]) or "nginx/lua/risk_engine.lua"
local ip = "192.0.2.77"
local state = {kv = {}, writes = {}, alerts = {}, calls = 0}
ngx = {
    ERR = 3, WARN = 4, INFO = 6, null = {},
    var = {realip_remote_addr = ip, remote_addr = ip},
    log = function(...) end,
}
local red = {}
function red:get(k) return state.kv[k] or ngx.null end
function red:set(k, val, ...)
    state.kv[k] = val
    state.writes[#state.writes+1] = {key=k, val=val, args={...}}
    return "OK"
end
function red:sadd(k, val) error("automatic ban must never call SADD: " .. k) end

-- Simulate the atomic EVAL contract; commit none when it fails.
function red:eval(script, nkeys, score_key, stamp_key, ban_key, bf_key, score, ttl, stamp, has_stamp, has_ban, ban_ttl)
    assert(type(script)=="string" and nkeys==4 and score_key:match("^risk:v1:"), "bad EVAL contract")
    if tonumber(has_stamp)==1 then self:set(stamp_key, stamp, "EX", ttl) end
    self:set(score_key, score, "EX", ttl)
    if tonumber(has_ban)==1 then self:set(ban_key, "1", "EX", ban_ttl) end
    return 1
end

package.loaded["redis_helper"] = {
    get_redis = function(db) assert(db==0); state.calls=state.calls+1; return red end,
    close = function(_) end,
}
package.loaded["telegram_alert"] = {
    send = function(payload) state.alerts[#state.alerts+1] = payload end,
}
metric_blocked = nil
local engine = assert(loadfile(source))()
local passed, failed = 0, 0
local function check(x, m) if not x then error(m, 2) end end
local function reset()
    state = {kv = {}, writes = {}, alerts = {}, calls = 0}
    ngx.var = {realip_remote_addr=ip, remote_addr=ip}
end
local function get_write(key)
    for i = #state.writes, 1, -1 do
        if state.writes[i].key == key then return state.writes[i] end
    end
    return nil
end
local function ttl(key)
    local w=get_write(key)
    check(w ~= nil, "missing write: " .. key)
    check(w.args[1] == "EX", "write must set TTL using EX: " .. key)
    check(type(w.args[2]) == "number", "TTL must be numeric: " .. key)
    return w.args[2]
end
local function request(fields, signals, score)
    local s = {client_ip = ip, risk = score or 0, signals = signals or {}}
    for k,v in pairs(fields) do s[k]=v end
    return {security=s}
end
local function case(name, fn)
    reset()
    local ok, err = pcall(fn)
    if ok then passed=passed+1; print("PASS  "..name)
    else failed=failed+1; print("FAIL  "..name..": "..tostring(err)) end
end
case("WAF SQLi keeps blocking but uses 15-minute temporary ban", function()
    local ctx = request({waf_sqli=true, block=true}, {"waf_sqli"}, 80)
    engine.run(ctx)
    check(ctx.security.risk_action == "block", "WAF must block")
    check(ttl("blacklist:"..ip) == 900, "automatic ban TTL must be 900 s")
    check(ttl("risk:v1:"..ip) == 7200, "elevated reputation TTL must be 7200 s")
    check(#state.alerts == 1, "WAF alert expected")
end)
case("moderate scanner creates bounded reputation but no ban", function()
    local ctx = request({bad_bot_scanner=true}, {"bad_bot_scanner"}, 20)
    engine.run(ctx)
    check(ttl("risk:v1:"..ip) == 3600, "normal reputation TTL must be 3600 s")
    check(get_write("blacklist:"..ip) == nil, "moderate risk must not auto-ban")
end)
case("repeated confirmed attacks can still cross block threshold", function()
    engine.run(request({bad_bot_scanner=true}, {"bad_bot_scanner"}, 30))
    engine.run(request({bad_bot_scanner=true}, {"bad_bot_scanner"}, 30))
    check(ttl("blacklist:"..ip) == 900, "elevated cumulative abuse must use bounded ban")
end)
case("rate-only requests remain non-punitive", function()
    local ctx=request({rate_limit_hard=true, block=true}, {"rate_limit_hard"}, 15)
    engine.run(ctx)
    check(ctx.security.risk_action == "limit", "rate-only should limit")
    check(#state.writes == 0, "rate-only must not write reputation/ban")
end)
case("context-only signals remain non-punitive", function()
    local ctx=request({}, {"dev_tool:curl"}, 40)
    engine.run(ctx)
    check(ctx.security.risk_action == "pass", "context should pass")
    check(#state.writes == 0, "context-only must not write")
end)
print(string.format("Risk reputation TTL tests: %d passed, %d failed, %d total", passed,failed,passed+failed))
if failed>0 then os.exit(1) end
