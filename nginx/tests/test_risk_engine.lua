-- Unit tests for Adaptive Security Gateway Risk Engine.
-- All Redis, ngx, metrics and Telegram dependencies are mocked.
-- Does not make HTTP requests or touch real Redis.
-- Run: luajit test_risk_engine.lua /usr/local/openresty/nginx/lua/risk_engine.lua

local module_path = arg[1] or "/usr/local/openresty/nginx/lua/risk_engine.lua"

_G.ngx = {
    var = {
        remote_addr = "172.20.0.1",
        realip_remote_addr = "172.20.0.1",
    },
    null = {},
    WARN = 4,
    INFO = 6,
    ERR = 3,
    log = function(...) end,
}

local kv, sets, writes, alerts
local red = {}

function red:get(key)
    return kv[key] or ngx.null
end

function red:set(key, value, ...)
    kv[key] = value
    writes[#writes + 1] = { method = "set", key = key, value = value }
    return "OK"
end

function red:sadd(key, value)
    sets[key] = sets[key] or {}
    sets[key][value] = true
    writes[#writes + 1] = { method = "sadd", key = key, value = value }
    return 1
end

package.loaded["redis_helper"] = {
    get_redis = function(db)
        assert(db == 0, "Risk Engine should use Redis DB 0")
        return red
    end,
    close = function(_) end,
}

package.loaded["telegram_alert"] = {
    send = function(payload)
        alerts[#alerts + 1] = payload
    end,
}

-- Keep metric mock nil: the module must handle an absent metrics collector.
_G.metric_blocked = nil
local chunk, load_err = loadfile(module_path)
assert(chunk, load_err)
local risk_engine = chunk()
assert(type(risk_engine.run) == "function", "Risk Engine run() is missing")

local ip = "172.20.0.1"
local passed, failed = 0, 0

local function reset()
    kv, sets, writes, alerts = {}, {}, {}, {}
    ngx.var = {
        remote_addr = ip,
        realip_remote_addr = ip,
        log_risk_score = "",
        log_security_block = "",
    }
end

local function check(condition, message)
    if not condition then error(message, 2) end
end

local function no_reputation_or_blacklist()
    check(kv["risk:v1:" .. ip] == nil, "context-only request wrote reputation")
    check(kv["blacklist:" .. ip] == nil, "context-only request wrote blacklist key")
    check(not (sets.blacklist_ips and sets.blacklist_ips[ip]), "IP was blacklisted")
    check(#writes == 0, "unexpected Redis writes: " .. #writes)
end

local function run_case(name, fn)
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

local function context_request()
    return {
        security = {
            client_ip = ip,
            risk = 45, -- would reach limit threshold after contextual bonuses
            signals = { "xff_private_client", "geo_private", "dev_tool:curl/" },
        },
    }
end

run_case("context-only signals do not rate-limit or write reputation", function()
    local ctx = context_request()
    risk_engine.run(ctx)
    check(ctx.security.risk_action == "pass", "expected pass, got " .. tostring(ctx.security.risk_action))
    check(ngx.var.log_security_block == "pass", "expected pass in nginx logging variable")
    no_reputation_or_blacklist()
end)

run_case("repeated context-only requests never accumulate into a ban", function()
    for _ = 1, 10 do
        local ctx = context_request()
        risk_engine.run(ctx)
        check(ctx.security.risk_action == "pass", "unexpected limit or block")
    end
    no_reputation_or_blacklist()
end)

run_case("missing JWT denies this request without an IP ban", function()
    local ctx = {
        security = {
            client_ip = ip,
            risk = 80,
            jwt_missing = true,
            signals = { "jwt_missing" },
        },
    }
    risk_engine.run(ctx)
    check(ctx.security.block == true, "missing JWT should block")
    check(ctx.security.risk_action == "block", "missing JWT action should be block")
    no_reputation_or_blacklist()
end)

run_case("pre-existing hard block remains in force", function()
    local ctx = {
        security = {
            client_ip = ip,
            risk = 20,
            block = true,
            signals = { "geo_private" },
        },
    }
    risk_engine.run(ctx)
    check(ctx.security.block == true, "prior block was cleared")
    check(ctx.security.risk_action == "block", "prior block action was lost")
    no_reputation_or_blacklist()
end)

run_case("strong WAF SQLi evidence still updates reputation and blocks", function()
    local ctx = {
        security = {
            client_ip = ip,
            risk = 80,
            block = true,
            waf_sqli = true,
            signals = { "waf_sqli" },
        },
    }
    risk_engine.run(ctx)
    check(ctx.security.risk_action == "block", "SQLi should be blocked")
    check(kv["risk:v1:" .. ip] ~= nil, "SQLi evidence did not update reputation")
    check(kv["blacklist:" .. ip] == "1", "SQLi evidence did not create temporary blacklist key")
    check(not (sets.blacklist_ips and sets.blacklist_ips[ip]), "auto-block must not enter permanent manual set")
end)

print(string.format("Risk Engine mock tests: %d passed, %d failed, %d total", passed, failed, passed + failed))
if failed > 0 then os.exit(1) end
