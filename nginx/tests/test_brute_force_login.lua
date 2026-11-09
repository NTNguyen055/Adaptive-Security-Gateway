-- Offline regression tests for nginx/lua/brute_force_login.lua.
-- Usage:
-- luajit test_brute_force_login.lua /path/to/brute_force_login.lua
-- No real Redis connections or HTTP requests are made.

local source = arg[1] or "nginx/lua/brute_force_login.lua"

local passed, failed = 0, 0
local original_getenv = os.getenv
local IP = "198.51.100.24"

local function eq(actual, expected, label)
    if actual ~= expected then
        error(
            (label or "value") .. ": expected " .. tostring(expected)
            .. ", got " .. tostring(actual),
            2
        )
    end
end

local function contains(text, wanted)
    return type(text) == "string"
        and text:find(wanted, 1, true) ~= nil
end

local function run_case(config, verify)
    local state = {
        evals = {},
        gets = {},
        sets = {},
        cache = {},
        cache_ttls = {},
        telegram = {},
        closed = 0,
        connected_db = nil,
    }

    os.getenv = function(name)
        if name == "BRUTE_FORCE_MAX_ATTEMPTS" then return "5" end
        if name == "BRUTE_FORCE_WINDOW" then return "300" end
        if name == "BRUTE_FORCE_COOLDOWN" then return "3600" end
        if name == "BRUTE_FORCE_RISK_PENALTY" then return "80" end
        return original_getenv(name)
    end

    local null_value = {}

    local red = {}

    function red:get(key)
        state.gets[#state.gets + 1] = key

        -- No existing lockout and no previous history.
        return null_value
    end

    function red:set(key, value, mode, ttl)
        state.sets[#state.sets + 1] = {
            key = key,
            value = value,
            mode = mode,
            ttl = ttl,
        }

        return true
    end

    function red:eval(script, nkeys, ...)
        local args = {...}

        state.evals[#state.evals + 1] = {
            script = script,
            nkeys = nkeys,
            args = args,
        }

        -- Reputation update script.
        if contains(script, "local low_ttl") then
            if config.reputation_error then
                return nil, "simulated reputation error"
            end

            return config.reputation_result or "80"
        end

        -- Atomic lockout + blacklist script.
        if contains(script, 'redis.call("SET", KEYS[2]') then
            if config.block_error then
                return nil, "simulated block persistence error"
            end

            return 1
        end

        -- Atomic failed-attempt counter script.
        if contains(script, 'redis.call("INCR", KEYS[1])') then
            if config.counter_error then
                return nil, "simulated counter error"
            end

            return config.attempt_count or 5
        end

        error("Unexpected Redis EVAL script")
    end

    package.loaded["redis_helper"] = {
        get_redis = function(db)
            state.connected_db = db

            if config.connection_error then
                return nil, "simulated Redis connection failure"
            end

            return red
        end,

        close = function(connection)
            eq(connection, red, "Redis connection passed to close")
            state.closed = state.closed + 1
        end,
    }

    package.loaded["telegram_alert"] = {
        send = function(payload)
            state.telegram[#state.telegram + 1] = payload

            if config.telegram_error then
                error("simulated Telegram failure")
            end

            return true
        end,
    }

    local cache = {}

    function cache:set(key, value, ttl)
        if config.cache_error then
            return nil, "simulated shared dictionary failure"
        end

        state.cache[key] = value
        state.cache_ttls[key] = ttl
        return true
    end

    _G.ngx = {
        null = null_value,

        ERR = 3,
        WARN = 4,
        INFO = 6,
        DEBUG = 7,
        ALERT = 1,

        var = {
            realip_remote_addr = IP,
            remote_addr = IP,
        },

        shared = {
            ip_cache = cache,
        },

        now = function()
            return 123.456
        end,

        log = function(...) end,
    }

    local chunk, load_error = loadfile(source)

    if not chunk then
        error("Cannot load source: " .. tostring(load_error))
    end

    local module = chunk()

    local ctx = {
        client_ip = IP,
        security = {
            risk = 0,
            signals = {},
        },
    }

    local result = module.record_failed_attempt(ctx)

    verify(ctx, state, result)
end

local function case(name, config, verify)
    local ok, err = pcall(run_case, config, verify)

    if ok then
        passed = passed + 1
        print("PASS  " .. name)
    else
        failed = failed + 1
        print("FAIL  " .. name .. ": " .. tostring(err))
    end
end

case(
    "threshold persists lockout and blacklist atomically",
    {
        attempt_count = 5,
        reputation_result = "80",
    },
    function(ctx, state, result)
        eq(result, false, "record_failed_attempt return")
        eq(state.connected_db, 0, "Redis database")
        eq(state.closed, 1, "Redis connection close")

        eq(#state.evals, 3, "Redis EVAL count")

        -- First EVAL: failed-attempt counter.
        local counter = state.evals[1]
        eq(counter.nkeys, 1, "counter KEYS count")
        eq(counter.args[1], "brute_force:fail:" .. IP, "counter key")
        eq(counter.args[2], 300, "counter window")
        eq(counter.args[3], 5, "counter max attempts")
        eq(counter.args[4], 3600, "counter cooldown")

        -- Second EVAL: atomic lockout + blacklist.
        local block = state.evals[2]
        eq(block.nkeys, 2, "block KEYS count")
        eq(block.args[1], "brute_force:lockout:" .. IP, "lockout key")
        eq(block.args[2], "blacklist:" .. IP, "blacklist key")
        eq(block.args[3], 3600, "shared block TTL")

        assert(
            contains(block.script, 'redis.call("SET", KEYS[1]')
                and contains(block.script, 'redis.call("SET", KEYS[2]'),
            "atomic script must write both keys"
        )

        -- Third EVAL: reputation.
        local reputation = state.evals[3]
        eq(reputation.nkeys, 1, "reputation KEYS count")
        eq(reputation.args[1], "risk:v1:" .. IP, "reputation key")
        eq(reputation.args[2], 80, "reputation increment")
        eq(reputation.args[3], 86400, "low reputation TTL")
        eq(reputation.args[4], 31536000, "high reputation TTL")

        assert(
            contains(reputation.script, "if updated >= 80 then"),
            "reputation TTL must depend on updated score"
        )

        eq(state.cache["bl:" .. IP], 1, "positive L1 cache")
        eq(state.cache_ttls["bl:" .. IP], 3600, "L1 cache TTL")

        eq(#state.telegram, 1, "Telegram alert count")
        eq(state.telegram[1].ip, IP, "Telegram IP")
        eq(state.telegram[1].score, 80, "Telegram reputation score")
        assert(
            contains(state.telegram[1].details, "TTL=3600 giây"),
            "Telegram must report configured cooldown"
        )

        eq(ctx.brute_force.action, "block", "brute-force action")
        eq(ctx.brute_force.attempt_count, 5, "attempt count")
        eq(ctx.security.block, true, "security block")
    end
)

case(
    "Redis block persistence failure does not send Telegram",
    {
        attempt_count = 5,
        block_error = true,
        reputation_result = "80",
    },
    function(ctx, state)
        eq(#state.evals, 3, "reputation must still be updated")
        eq(state.cache["bl:" .. IP], nil, "failed block must not update cache")
        eq(#state.telegram, 0, "Telegram must not be sent")
        eq(state.closed, 1, "Redis connection close")
        eq(ctx.security.block, true, "request block flag")
    end
)

case(
    "invalid reputation result does not crash module",
    {
        attempt_count = 5,
        reputation_result = "not-a-number",
    },
    function(ctx, state)
        eq(#state.evals, 3, "Redis EVAL count")
        eq(state.cache["bl:" .. IP], 1, "block cache")
        eq(#state.telegram, 1, "block alert still sent")
        eq(state.telegram[1].score, 80, "fallback Telegram score")
        eq(ctx.security.block, true, "security block")
    end
)

case(
    "reputation script supports score below threshold",
    {
        attempt_count = 5,
        reputation_result = "79",
    },
    function(ctx, state)
        local reputation = state.evals[3]

        assert(
            contains(reputation.script, "local low_ttl")
                and contains(reputation.script, "local high_ttl")
                and contains(reputation.script, "if updated >= 80 then"),
            "reputation script must implement both TTL branches"
        )

        eq(reputation.args[3], 86400, "low score TTL")
        eq(reputation.args[4], 31536000, "high score TTL")
        eq(state.telegram[1].score, 79, "Telegram reputation score")
    end
)

case(
    "Redis connection failure does not punish or block client",
    {
        connection_error = true,
    },
    function(ctx, state, result)
        eq(result, false, "record_failed_attempt return")
        eq(#state.evals, 0, "no EVAL without Redis")
        eq(#state.telegram, 0, "no Telegram without Redis")
        eq(state.closed, 0, "no connection to close")
        eq(ctx.brute_force, nil, "no brute-force state")
        eq(ctx.security.block, nil, "no security block")
    end
)

case(
    "counter failure stops processing without false block",
    {
        counter_error = true,
    },
    function(ctx, state, result)
        eq(result, false, "record_failed_attempt return")
        eq(#state.evals, 1, "only counter EVAL")
        eq(#state.telegram, 0, "no Telegram")
        eq(state.cache["bl:" .. IP], nil, "no cache update")
        eq(state.closed, 1, "Redis connection close")
        eq(ctx.security.block, nil, "no security block")
    end
)

os.getenv = original_getenv

print(string.format(
    "Brute Force Login regression tests: %d passed, %d failed, %d total",
    passed,
    failed,
    passed + failed
))

if failed > 0 then
    os.exit(1)
end
