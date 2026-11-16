-- Offline regression tests for nginx/lua/rate_limit_redis.lua.
-- Usage: luajit test_rate_limit_redis.lua /path/to/rate_limit_redis.lua
-- No real Redis connections or HTTP requests are made.

local source = arg[1] or "/usr/local/openresty/nginx/lua/rate_limit_redis.lua"
local passed, failed = 0, 0
local original_getenv = os.getenv

-- Make the expected limit/window deterministic even when a local .env differs.
os.getenv = function(name)
    if name == "REDIS_RATE_LIMIT" then return "30" end
    if name == "REDIS_RL_WINDOW" then return "60" end
    return original_getenv(name)
end

local function eq(actual, expected, label)
    if actual ~= expected then
        error((label or "value") .. ": expected " .. tostring(expected)
            .. ", got " .. tostring(actual), 2)
    end
end

local function contains(values, wanted)
    for _, v in ipairs(values or {}) do
        if v == wanted then return true end
    end
    return false
end

local function run_case(name, config, verify)
    local state = {evals = {}, init_calls = 0, pooled = 0, closed = 0, db = nil}
    local red = {}

    function red:init_pipeline()
        state.init_calls = state.init_calls + 1
    end

    function red:eval(script, nkeys, k1, k2, now, window)
        table.insert(state.evals, {
            script = script, nkeys = nkeys, key = k1,
            sequence_key = k2, now = now, window = window,
        })
    end

    function red:commit_pipeline()
        if config.transport_error then
            return nil, "simulated transport timeout"
        end
        return config.replies
    end

    function red:close()
        state.closed = state.closed + 1
    end

    package.loaded["redis_helper"] = {
        get_redis = function(db)
            state.db = db
            if config.connection_error then return nil, "simulated connection refused" end
            return red
        end,
        close = function(connection)
            eq(connection, red, "pooled Redis connection")
            state.pooled = state.pooled + 1
        end,
    }

    _G.ngx = {
        WARN = 4,
        ERR = 3,
        var = {
            remote_addr = "198.51.100.24",
            realip_remote_addr = "198.51.100.24",
            uri = "/test-resource/",
        },
        now = function() return 123.456 end,
        log = function(...) end,
    }
    _G.metric_blocked = nil

    local chunk, load_error = loadfile(source)
    if not chunk then error("Cannot load source: " .. tostring(load_error)) end
    local module = chunk()
    local ctx = {
        security = {
            client_ip = "198.51.100.24",
            risk = config.initial_risk or 0,
            signals = {},
        },
    }
    module.run(ctx)
    verify(ctx, state)
end

local cases = {
    {
        "healthy pipeline uses two unique-member scripts and passes",
        {replies = {5, 4}},
        function(ctx, state)
            eq(state.db, 0, "Redis database")
            eq(state.init_calls, 1, "pipeline count")
            eq(#state.evals, 2, "EVAL count")
            eq(state.evals[1].nkeys, 2, "number of Redis KEYS")
            eq(state.evals[1].key, "rrl:198.51.100.24", "global key")
            eq(state.evals[1].sequence_key, "rrl:198.51.100.24:seq", "global seq key")
            eq(state.evals[2].key, "rrl:198.51.100.24:/test-resource/", "URI key")
            eq(state.evals[2].sequence_key, "rrl:198.51.100.24:/test-resource/:seq", "URI seq key")
            eq(state.evals[1].now, 123456, "milliseconds")
            eq(state.evals[1].window, 60, "window seconds")
            assert(state.evals[1].script:find("redis.call('INCR', seq_key)", 1, true), "missing unique-member sequence")
            assert(state.evals[1].script:find("redis.call('PEXPIRE', seq_key, window_ms)", 1, true), "missing sequence TTL")
            assert(not ctx.security.block, "normal request should not be blocked")
            assert(not ctx.security.redis_rl_error, "healthy response marked as error")
            eq(state.pooled, 1, "pooled connections")
            eq(state.closed, 0, "force-closed connections")
        end,
    },
    {
        "near-limit traffic warns without increasing risk",
        {replies = {22, 5}, initial_risk = 17},
        function(ctx, state)
            eq(ctx.security.redis_rate_warn, true, "warning flag")
            eq(ctx.security.risk, 17, "warning must not increase risk")

            assert(not ctx.security.block,
                "near-limit traffic must not be blocked")

            assert(contains(ctx.security.signals, "redis_rate_warn"),
                "warning signal missing")

            eq(state.pooled, 1, "pooled Redis connection")
        end,
    },
    {
        "over-limit Redis counts trigger a request block",
        {replies = {31, 22}},
        function(ctx, state)
            eq(ctx.security.redis_rate_exceeded, true, "rate-exceeded flag")
            eq(ctx.security.block, true, "request block flag")
            assert(contains(ctx.security.signals, "redis_rate_exceeded"), "rate signal missing")
            eq(state.pooled, 1, "pooled connections")
        end,
    },
    {
        "Redis connection outage does not punish client IP",
        {connection_error = true, initial_risk = 17},
        function(ctx, state)
            eq(ctx.security.redis_rl_fail, true, "Redis outage signal")
            eq(ctx.security.risk, 17, "risk must not increase because Redis is down")
            assert(not ctx.security.block, "infrastructure failure cannot imply abuse")
            eq(#state.evals, 0, "no Redis EVAL when connection fails")
            eq(state.pooled, 0, "no connection to pool")
            eq(state.closed, 0, "no connected client to close")
        end,
    },
    {
        "whole pipeline failure is not interpreted as zero counts",
        {transport_error = true},
        function(ctx, state)
            eq(ctx.security.redis_rl_error, true, "pipeline error flag")
            eq(ctx.security.risk, 0, "risk increment on infrastructure failure")
            assert(not ctx.security.redis_rate_exceeded, "pipeline failure called over-limit")
            eq(state.closed, 1, "force close on transport failure")
            eq(state.pooled, 0, "pooled broken connection")
        end,
    },
    {
        "one failed EVAL reply is not interpreted as zero counts",
        {replies = {{false, "ERR simulated script failure"}, 4}},
        function(ctx, state)
            eq(ctx.security.redis_rl_error, true, "EVAL error flag")
            eq(ctx.security.risk, 0, "risk increment on EVAL failure")
            assert(not ctx.security.redis_rate_exceeded, "EVAL failure called over-limit")
            eq(state.pooled, 1, "healthy transport returned to pool")
        end,
    },
    {
        "wrong-type replies are rejected instead of coerced",
        {replies = {"5", 4}},
        function(ctx, state)
            eq(ctx.security.redis_rl_error, true, "reply type validation")
            assert(not ctx.security.redis_rate_exceeded, "invalid reply called over-limit")
            eq(state.pooled, 1, "pooled connections")
        end,
    },
}

for _, case in ipairs(cases) do
    local ok, err = pcall(run_case, case[1], case[2], case[3])
    if ok then
        passed = passed + 1
        print("PASS  " .. case[1])
    else
        failed = failed + 1
        print("FAIL  " .. case[1] .. ": " .. tostring(err))
    end
end

os.getenv = original_getenv
print(string.format("Redis Rate Limiter mock tests: %d passed, %d failed, %d total", passed, failed, passed + failed))
if failed > 0 then os.exit(1) end
