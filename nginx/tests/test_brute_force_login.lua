
-- P0.2.4-A3.2: NAT-aware Brute Force regression tests.
-- No real Redis or Telegram calls.
-- Run: luajit nginx/tests/test_brute_force_login.lua

local source = (arg and arg[1])
    or "nginx/lua/brute_force_login.lua"

local passed, failed = 0, 0
local IP = "198.51.100.24"
local original_getenv = os.getenv

local function eq(actual, expected, message)
    assert(
        actual == expected,
        (message or "mismatch")
        .. " expected=" .. tostring(expected)
        .. " actual=" .. tostring(actual)
    )
end

local function harness(options)
    options = options or {}

    local state = {
        evals = {},
        writes = {},
        gets = {},
        alerts = {},
        closed = 0,
        fallback = {},
        secondary = {},
        kv = {},
        ttl = {},
        db = nil,
    }

    local null = {}

    local shared = {
        brute_force_cache = {
            get = function(_, key)
                return state.fallback[key]
            end,
            set = function(_, key, value, ttl)
                if options.primary_error then
                    return nil, "shared memory full"
                end
                state.fallback[key] = value
                state.ttl[key] = ttl
                return true
            end,
        },
        ip_cache = {
            get = function(_, key)
                return state.secondary[key]
            end,
            set = function(_, key, value, ttl)
                state.secondary[key] = value
                state.ttl[key] = ttl
                return true
            end,
        },
    }

    if options.degraded then
        state.fallback["bf:gateway_degraded"] = 1
    end

    if options.remove_primary then
        shared.brute_force_cache = nil
    end

    if options.remove_secondary then
        shared.ip_cache = nil
    end

    local red = {}

    function red:get(key)
        state.gets[#state.gets + 1] = key

        if options.read_error then
            return nil, "GET unavailable"
        end

        if key == "brute_force:fail:" .. IP then
            return options.counter
                or state.kv[key]
                or null
        end

        if key == "brute_force:history:" .. IP then
            return null
        end

        error("Unexpected Redis GET: " .. tostring(key))
    end

    function red:set(key, value, mode, ttl)
        assert(
            not key:match("^blacklist:")
            and not key:match("^brute_force:lockout:")
            and not key:match("^risk:v1:"),
            "Unauthorized IP punishment write: "
                .. tostring(key)
        )

        state.writes[#state.writes + 1] = {
            key = key,
            value = value,
            mode = mode,
            ttl = ttl,
        }

        state.kv[key] = value
        return true
    end

    function red:eval(script, nkeys, ...)
        local args = {...}

        state.evals[#state.evals + 1] = {
            script = script,
            nkeys = nkeys,
            args = args,
        }

        assert(
            nkeys == 1
            and args[1] == "brute_force:fail:" .. IP,
            "Only failed-login telemetry may be written"
        )

        assert(
            script:find(
                'redis.call("INCR", KEYS[1])',
                1,
                true
            ),
            "Atomic failure counter missing"
        )

        assert(
            not script:find("blacklist", 1, true)
            and not script:find("lockout", 1, true)
            and not script:find("risk:v1", 1, true),
            "Redis EVAL contains unauthorized IP punishment"
        )

        if options.eval_error then
            return nil, "EVAL failed"
        end

        return options.next_count or 5
    end

    package.loaded["redis_helper"] = {
        get_redis = function(db)
            state.db = db

            if options.redis_down then
                return nil, "connection unavailable"
            end

            return red
        end,

        close = function(connection)
            eq(connection, red, "Redis connection")
            state.closed = state.closed + 1
        end,
    }

    package.loaded["telegram_alert"] = {
        send = function(payload)
            state.alerts[#state.alerts + 1] = payload
            return true
        end,
    }

    _G.ngx = {
        null = null,
        ERR = 3,
        WARN = 4,
        INFO = 6,
        DEBUG = 7,
        ALERT = 1,
        CRIT = 2,

        var = {
            remote_addr = IP,
            realip_remote_addr = IP,
        },

        shared = shared,

        now = function()
            return 123.456
        end,

        log = function(...) end,
    }

    os.getenv = function(name)
        if name == "BRUTE_FORCE_MAX_ATTEMPTS" then
            return "5"
        end

        if name == "BRUTE_FORCE_WINDOW" then
            return "300"
        end

        return original_getenv(name)
    end

    local module = assert(loadfile(source))()
    return module, state
end

local function case(name, fn)
    local ok, err = pcall(fn)
    os.getenv = original_getenv

    if ok then
        passed = passed + 1
        print("PASS " .. name)
    else
        failed = failed + 1
        print("FAIL " .. name .. ": " .. tostring(err))
    end
end

case("clean pre-login allows authentication", function()
    local module, state = harness()
    eq(module.check_prelogin({client_ip = IP}), false)
    eq(state.gets[1], "brute_force:fail:" .. IP)
    eq(#state.gets, 1)
    eq(state.closed, 1)
end)

case("legacy IP lockout is no longer consulted", function()
    local module, state = harness({counter = "2"})
    local ctx = {client_ip = IP}

    eq(module.check_prelogin(ctx), false)
    eq(ctx.brute_force.attempt_count, 2)
    eq(#state.gets, 1)
end)

case("five failures cannot lock shared NAT IP", function()
    local module = harness({counter = "5"})
    local ctx = {client_ip = IP}

    eq(module.check_prelogin(ctx), false)
    eq(ctx.brute_force.threshold_observed, true)
end)

case("many failures remain observe-only", function()
    local module = harness({counter = "100"})
    eq(module.check_prelogin({client_ip = IP}), false)
end)

case("invalid counter fails closed", function()
    local module = harness({counter = "invalid"})
    local result, err = module.check_prelogin({client_ip = IP})

    eq(result, nil)
    assert(err ~= nil)
end)

case("Redis outage fails closed without IP ban", function()
    local module, state = harness({redis_down = true})
    local result, err = module.check_prelogin({client_ip = IP})

    eq(result, nil)
    assert(err ~= nil)
    eq(#state.gets, 0)
end)

case("Redis read failure fails closed", function()
    local module, state = harness({read_error = true})
    local result, err = module.check_prelogin({client_ip = IP})

    eq(result, nil)
    assert(err ~= nil)
    eq(state.closed, 1)
end)

case("degraded marker prevents unsafe login", function()
    local module, state = harness({degraded = true})
    local result, err = module.check_prelogin({client_ip = IP})

    eq(result, nil)
    assert(err ~= nil)
    eq(state.db, nil)
end)

case("missing IP cannot bypass accounting", function()
    local module, state = harness()

    ngx.var.remote_addr = nil
    ngx.var.realip_remote_addr = nil

    local result, err = module.check_prelogin({})

    eq(result, nil)
    assert(err ~= nil)
    eq(state.db, nil)
end)

case("fifth failure records telemetry without punishment", function()
    local module, state = harness({next_count = 5})
    local ctx = {
        client_ip = IP,
        security = {risk = 0, signals = {}},
    }

    eq(module.record_failed_attempt(ctx), true)

    eq(#state.evals, 1)
    eq(state.evals[1].args[2], 300)

    eq(ctx.brute_force.action, "observe_threshold")
    eq(ctx.security.block, nil)
    eq(ctx.security.risk, 0)
    eq(#ctx.security.signals, 0)

    eq(#state.alerts, 1)
    eq(state.closed, 1)

    eq(state.fallback["bf:emergency:" .. IP], nil)
    eq(state.secondary["bl:" .. IP], nil)
end)

case("sixth failure does not repeat alert or ban", function()
    local module, state = harness({next_count = 6})
    local ctx = {
        client_ip = IP,
        security = {risk = 0, signals = {}},
    }

    eq(module.record_failed_attempt(ctx), true)
    eq(#state.evals, 1)
    eq(#state.alerts, 0)
    eq(ctx.security.block, nil)
    eq(ctx.brute_force.action, "observe_threshold")
end)

case("subthreshold failure remains telemetry-only", function()
    local module, state = harness({next_count = 3})
    local ctx = {client_ip = IP}

    eq(module.record_failed_attempt(ctx), true)
    eq(ctx.brute_force.action, "observe")
    eq(#state.alerts, 0)
end)

case("Redis write outage creates no emergency IP lock", function()
    local module, state = harness({redis_down = true})

    local result = module.record_failed_attempt({
        client_ip = IP
    })

    eq(result, false)
    eq(state.fallback["bf:gateway_degraded"], 1)
    eq(state.ttl["bf:gateway_degraded"], 10)

    eq(state.fallback["bf:emergency:" .. IP], nil)
    eq(state.secondary["bl:" .. IP], nil)
end)

case("counter EVAL failure sets bounded degraded state", function()
    local module, state = harness({eval_error = true})

    eq(module.record_failed_attempt({client_ip = IP}), false)

    eq(state.fallback["bf:gateway_degraded"], 1)
    eq(state.ttl["bf:gateway_degraded"], 10)
    eq(state.closed, 1)
end)

case("secondary shared dictionary fallback works", function()
    local module, state = harness({
        redis_down = true,
        primary_error = true,
    })

    module.record_failed_attempt({client_ip = IP})

    eq(state.fallback["bf:gateway_degraded"], nil)
    eq(state.secondary["bf:gateway_degraded"], 1)
end)

case("missing shared dictionaries reports degraded failure", function()
    local module = harness({
        redis_down = true,
        remove_primary = true,
        remove_secondary = true,
    })

    local result, err = module.record_failed_attempt({
        client_ip = IP
    })

    eq(result, false)
    assert(
        err:find("without shared latch", 1, true) ~= nil
    )
end)

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
