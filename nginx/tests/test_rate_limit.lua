-- Mock regression tests for nginx/lua/rate_limit.lua.
-- Usage: luajit test_rate_limit.lua /tmp/rate_limit_under_test.lua
-- No HTTP requests, Redis connections, or blacklist writes.

local source = (arg and arg[1]) or "nginx/lua/rate_limit.lua"
local state = { mode = "ok", init_calls = 0, requests = {} }

ngx = {
    ERR = 3, WARN = 4,
    var = { realip_remote_addr = "192.0.2.10", remote_addr = "192.0.2.10" },
    log = function(...) end,
    timer = { at = function() error("unexpected async blacklist timer") end },
    shared = {},
}
package.loaded["redis_helper"] = nil
package.preload["redis_helper"] = function()
    error("Local Rate Limiter must not depend on Redis")
end
package.preload["resty.limit.req"] = function()
    return {
        new = function(dict_name, rate, burst)
            state.init_calls = state.init_calls + 1
            assert(dict_name == "limit_req_store")
            assert(rate > 0 and burst >= 0)
            return {
                incoming = function(self, key, commit)
                    state.requests[#state.requests + 1] = {key = key, commit = commit}
                    if state.mode == "ok" then return 0 end
                    if state.mode == "burst" then return 0.15 end
                    if state.mode == "reject" then return nil, "rejected" end
                    return nil, "synthetic limiter error"
                end,
            }
        end,
    }
end

local module = assert(loadfile(source))()
assert(type(module.run) == "function")
local passed, failed = 0, 0

local function check(v, explanation)
    if not v then error(explanation, 2) end
end
local function request(mode, ip, initial_risk)
    state.mode = mode
    local ctx = { security = { client_ip = ip or "192.0.2.10",
                               risk = initial_risk or 0, signals = {} } }
    module.run(ctx)
    return ctx
end
local function run_case(name, fn)
    local success, err = pcall(fn)
    if success then
        passed = passed + 1
        print("PASS  " .. name)
    else
        failed = failed + 1
        print("FAIL  " .. name .. ": " .. tostring(err))
    end
end

run_case("normal request passes and uses normalized client IP", function()
    local ctx = request("ok", "192.0.2.50", 12)
    check(not ctx.security.block, "normal request blocked")
    check(ctx.security.risk == 12, "risk mutated")
    local last = state.requests[#state.requests]
    check(last.key == "192.0.2.50" and last.commit == true, "limiter key/commit incorrect")
end)

run_case("burst limits this request without adding 80 risk", function()
    local ctx = request("burst", "192.0.2.10", 17)
    check(ctx.security.block == true, "burst should block request")
    check(ctx.security.rate_limit_burst == true, "burst flag missing")
    check(ctx.security.signals[1] == "rate_limit_burst", "burst signal missing")
    check(ctx.security.risk == 17, "burst should not increase reputation input")
end)

run_case("hard rejection limits this request without adding 80 risk", function()
    local ctx = request("reject", "192.0.2.10", 29)
    check(ctx.security.block == true, "hard rejection should block request")
    check(ctx.security.rate_limit_hard == true, "hard flag missing")
    check(ctx.security.signals[1] == "rate_limit_hard", "hard signal missing")
    check(ctx.security.risk == 29, "hard limit should not add risk")
end)

run_case("limiter error is logged but not mistaken for a rejection", function()
    local ctx = request("error", "192.0.2.10", 0)
    check(not ctx.security.block, "limiter operational error should not act as abuse")
    check(not ctx.security.rate_limit_hard, "unexpected hard flag")
end)

run_case("limiter instance is cached per worker", function()
    check(state.init_calls == 1, "limiter created " .. state.init_calls .. " times")
    check(#state.requests == 4, "unexpected request count")
end)

print(string.format("Local Rate Limiter mock tests: %d passed, %d failed, %d total",
    passed, failed, passed + failed))
if failed > 0 then os.exit(1) end
