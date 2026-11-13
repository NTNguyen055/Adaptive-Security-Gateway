-- Stage 1.4 batch 2: deterministic time-based reputation-decay regression tests.
-- Usage: luajit test_risk_decay.lua /tmp/risk_engine_14.lua
-- No network, Redis server, or Telegram messages are used.
local source = (arg and arg[1]) or "nginx/lua/risk_engine.lua"
local ip = "192.0.2.88"
local state = {now=1000, kv={}, writes={}, calls=0, alerts={}}
local old_getenv = os.getenv
local test_factor = "0.1"
os.getenv = function(key)
    if key == "RISK_DECAY_ENABLED" then return "true" end
    if key == "RISK_DECAY_FACTOR" then return test_factor end
    return old_getenv(key)
end
ngx = {
    ERR=3, WARN=4, INFO=6, null={},
    var={realip_remote_addr=ip, remote_addr=ip},
    now=function() return state.now end,
    log=function(...) end,
}
local red = {}
function red:get(key)
    state.calls = state.calls + 1
    return state.kv[key] or ngx.null
end
function red:set(key, val, ...)
    state.kv[key] = val
    state.writes[#state.writes+1] = {key=key, val=val, args={...}}
    return "OK"
end
function red:sadd(key, val)
    error("Risk Engine must not insert automatic bans into blacklist_ips")
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
    get_redis = function(db) assert(db==0); return red end,
    close = function(_) end,
}
package.loaded["telegram_alert"] = {
    send = function(payload) state.alerts[#state.alerts+1] = payload end,
}
metric_blocked = nil
local engine = assert(loadfile(source))()
local passed, failed = 0, 0
local function check(v, msg) if not v then error(msg, 2) end end
local function approx(a, b)
    check(math.abs(a-b) < 0.15, "score expected "..b..", got "..tostring(a))
end
local function reset()
    test_factor = "0.1"
    state = {now=1000, kv={}, writes={}, calls=0, alerts={}}
    ngx.var = {realip_remote_addr=ip, remote_addr=ip}
end
local function abuse()
    local ctx={security={client_ip=ip,risk=20,signals={"bad_bot_scanner"},bad_bot_scanner=true}}
    engine.run(ctx)
    return ctx
end
local function get_write(key)
    for i=#state.writes,1,-1 do
        if state.writes[i].key==key then return state.writes[i] end
    end
end
local function run_case(name, fn)
    reset()
    local ok, err=pcall(fn)
    if ok then passed=passed+1; print("PASS  "..name)
    else failed=failed+1; print("FAIL  "..name..": "..tostring(err)) end
end
run_case("decay reduces prior reputation after five minutes", function()
    local first=abuse()
    approx(first.security.risk_final,30)
    check(tonumber(state.kv["risk:v1:last_seen:"..ip]) == 1000, "timestamp not stored")
    state.now=1300
    local second=abuse()
    approx(second.security.risk_final,57) -- 30*0.9 + 30
    check(tonumber(state.kv["risk:v1:last_seen:"..ip]) == 1300, "timestamp not advanced")
end)
run_case("frequent confirmed attacks do not get premature decay", function()
    abuse()
    state.now=1100
    approx(abuse().security.risk_final,60)
end)
run_case("six decay periods lower NAT shared-IP reputation", function()
    abuse()
    state.now=2800  -- 1800 seconds = six 5-minute periods
    local ctx=abuse()
    approx(ctx.security.risk_final,30 * (0.9^6) + 30)
    check(ctx.security.risk_action ~= "block", "stale reputation should not force a block")
end)
run_case("clean requests cannot refresh punishment or timestamps", function()
    abuse()
    local write_count=#state.writes
    local read_count=state.calls
    state.now=2500
    local ctx={security={client_ip=ip,risk=40,signals={"dev_tool:curl"}}}
    engine.run(ctx)
    check(ctx.security.risk_action=="pass", "context-only request not allowed")
    check(#state.writes==write_count and state.calls==read_count, "clean/context traffic touched reputation")
    check(tonumber(state.kv["risk:v1:last_seen:"..ip]) == 1000, "timestamp refreshed by clean request")
end)
run_case("legacy score without timestamp is not silently forgiven", function()
    state.kv["risk:v1:"..ip]="50.00"
    state.now=3000
    local ctx=abuse()
    approx(ctx.security.risk_final,80)
    check(ctx.security.risk_action == "block", "legacy high score unexpectedly bypassed")
    check(tonumber(state.kv["risk:v1:last_seen:"..ip]) == 3000, "legacy score timestamp not initialized")
    check(state.kv["blacklist:"..ip]=="1", "expected temporary auto-block")
end)
run_case("clock moving backwards cannot forgive reputation", function()
    state.now=2000
    abuse()
    state.now=1999
    approx(abuse().security.risk_final,60)
end)
run_case("decay factor is clamped to prevent negative reputation", function()
    test_factor="2.5"
    abuse()
    state.now=1300
    approx(abuse().security.risk_final,30)
end)
run_case("timestamp TTL matches reputation TTL", function()
    abuse()
    local key="risk:v1:"..ip
    local stamp="risk:v1:last_seen:"..ip
    local a,b=get_write(key),get_write(stamp)
    check(a and b, "reputation/timestamp write missing")
    check(a.args[1]=="EX" and b.args[1]=="EX", "must use TTL")
    check(a.args[2]==b.args[2] and a.args[2]==3600, "initial reputation TTL mismatch")
end)
print(string.format("Time-based risk decay tests: %d passed, %d failed, %d total",passed,failed,passed+failed))
if failed>0 then os.exit(1) end
