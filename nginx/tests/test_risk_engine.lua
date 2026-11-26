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
local conflicts_left, eval_calls
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


-- Simulate the atomic EVAL contract; commit none when it fails.
function red:eval(script, nkeys, score_key, stamp_key, ban_key, bf_key, score, ttl, stamp, has_stamp, has_ban, ban_ttl, old_score, old_stamp, old_bf)
    assert(type(script)=="string" and nkeys==4 and score_key:match("^risk:v1:"), "bad EVAL contract")
    eval_calls = eval_calls + 1
    if conflicts_left > 0 then
        conflicts_left = conflicts_left - 1
        kv[score_key] = "30.00"  -- another confirmed request committed first
        return 0
    end
    assert(old_score == (kv[score_key] or "__ASG_MISSING__"), "stale snapshot was not reloaded")
    if tonumber(has_stamp)==1 then self:set(stamp_key, stamp, "EX", ttl) end
    self:set(score_key, score, "EX", ttl)
    if tonumber(has_ban)==1 then self:set(ban_key, "1", "EX", ban_ttl) end
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
    conflicts_left, eval_calls = 0, 0
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
    check(kv["blacklist:" .. ip] == nil, "Risk Engine must not create an IP ban from WAF score")
    check(not (sets.blacklist_ips and sets.blacklist_ips[ip]), "auto-block must not enter permanent manual set")
end)

run_case("CAS conflict reloads reputation before a second write", function()
    conflicts_left = 1
    local ctx = { security = { client_ip = ip, risk = 20,
        bad_bot_scanner = true, signals = {"bad_bot_scanner"} } }
    risk_engine.run(ctx)
    check(eval_calls == 2, "expected CAS retry")
    check(ctx.security.risk_final == 60, "lost concurrent reputation increment")
    check(kv["risk:v1:" .. ip] == "60.00", "stored reputation lost update")
    check(not ctx.security.redis_risk_error, "successful retry marked as failure")
end)

run_case("shared NAT login history cannot amplify IP risk", function()
    kv["brute_force:history:" .. ip] = "100:5,90:6,80:7"

    local ctx = {
        security = {
            client_ip = ip,
            risk = 10,
            bad_bot_scanner = true,
            signals = {"bad_bot_scanner"},
        },
    }

    risk_engine.run(ctx)

    check(
        ctx.security.risk_final == 20,
        "Login failure history increased shared-IP risk"
    )

    check(
        kv["blacklist:" .. ip] == nil,
        "Login history caused an automatic IP ban"
    )
end)

run_case("brute-force signal alone cannot punish IP", function()
    local ctx = {
        security = {
            client_ip = ip,
            risk = 25,
            brute_force_attack = true,
            signals = {"brute_force_attack"},
        },
    }

    risk_engine.run(ctx)

    check(
        ctx.security.risk_action == "pass",
        "Login-failure signal unexpectedly punished the IP"
    )

    no_reputation_or_blacklist()
end)

run_case("P05 XFF spoof alone must not persist IP reputation", function()
    for attempt = 1, 2 do
        local ctx = {
            security = {
                client_ip = ip,
                risk = 20,
                xff_spoof = true,
                signals = {"xff_spoof"},
            },
        }

        risk_engine.run(ctx)

        check(ctx.security.risk_action == "pass",
            "XFF spoof alone escalated on request " .. attempt)

        no_reputation_or_blacklist()
    end

end)

run_case("P05 private XFF chain alone must remain contextual", function()
    for attempt = 1, 2 do
        local ctx = {
            security = {
                client_ip = ip,
                risk = 15,
                xff_private_chain = true,
                signals = {"xff_private_chain"},
            },
        }

        risk_engine.run(ctx)

        check(ctx.security.risk_action == "pass",
            "Private XFF chain alone escalated on request " .. attempt)

        no_reputation_or_blacklist()
    end

end)

run_case("P05 headless alone must remain request-scoped limit", function()
    for attempt = 1, 2 do
        local ctx = {
            security = {
                client_ip = ip,
                risk = 60,
                bad_bot_headless = true,
                signals = {"bad_bot_headless"},
            },
        }

        risk_engine.run(ctx)

        check(ctx.security.risk_action == "limit",
            "Headless signal escalated beyond request-only limit")

        no_reputation_or_blacklist()
    end

end)

run_case("P05 rate-only plus XFF spoof must not poison reputation", function()
    local ctx = {
        security = {
            client_ip = ip,
            risk = 20,
            block = true,
            rate_limit_hard = true,
            xff_spoof = true,
            signals = {"rate_limit_hard", "xff_spoof"},
        },
    }

    risk_engine.run(ctx)

    check(ctx.security.rate_only_limited == true,
        "Rate-only mitigation marker missing")
    check(ctx.security.risk_action == "limit",
        "Rate-only request was promoted to stronger punishment")

    no_reputation_or_blacklist()
end)

run_case("P05 JWT missing with XFF spoof remains denied", function()
    local ctx = {
        security = {
            client_ip = ip,
            risk = 20,
            jwt_missing = true,
            xff_spoof = true,
            signals = {"jwt_missing", "xff_spoof"},
        },
    }

    risk_engine.run(ctx)

    check(ctx.security.block == true,
        "JWT missing was not denied")

    check(ctx.security.risk_action == "block",
        "XFF spoof caused authentication denial to be lost")

    no_reputation_or_blacklist()
end)

run_case("P05 headless never downgrades an existing hard block", function()
    local ctx = {
        security = {
            client_ip = ip,
            risk = 60,
            block = true,
            bad_bot_headless = true,
            signals = {"bad_bot_headless"},
        },
    }

    risk_engine.run(ctx)

    check(ctx.security.block == true,
        "Existing security block was cleared")

    check(ctx.security.risk_action == "block",
        "Headless-only policy downgraded an existing block")

    no_reputation_or_blacklist()
end)

run_case("P05 XFF chain abuse blocks request without IP reputation", function()
    local ctx = {
        security = {
            client_ip = ip,
            risk = 100,
            block = true,
            xff_chain_abuse = true,
            signals = {"xff_chain_abuse"},
        },
    }

    risk_engine.run(ctx)

    check(ctx.security.block == true,
        "XFF chain abuse block was lost")

    check(ctx.security.risk_action == "block",
        "XFF chain abuse must still deny the request")

    no_reputation_or_blacklist()
end)

run_case("P05 WAF SQLi with XFF chain still records WAF reputation", function()
    local ctx = {
        security = {
            client_ip = ip,
            risk = 100,
            block = true,
            waf_sqli = true,
            xff_chain_abuse = true,
            signals = {"waf_sqli", "xff_chain_abuse"},
        },
    }

    risk_engine.run(ctx)

    check(ctx.security.risk_action == "block",
        "WAF SQLi block was lost")

    check(kv["risk:v1:" .. ip] ~= nil,
        "WAF SQLi reputation was not recorded")

    check(kv["blacklist:" .. ip] == nil,
        "Risk Engine issued an unauthorized IP ban")
end)

-- ============================================================
-- Risk configuration negative contract tests
-- RED phase: no production configuration fix yet.
-- ============================================================

local function with_risk_env(overrides, fixed_now, fn)
    local original_getenv = os.getenv
    local original_now = ngx.now

    os.getenv = function(name)
        if overrides[name] ~= nil then
            return overrides[name]
        end
        return original_getenv(name)
    end

    if fixed_now ~= nil then
        ngx.now = function() return fixed_now end
    end

    local ok, err = pcall(fn)

    os.getenv = original_getenv
    ngx.now = original_now

    if not ok then
        error(err, 0)
    end
end

run_case("P05 invalid high thresholds cannot disable WAF risk block", function()
    with_risk_env({
        RISK_LIMIT_THRESHOLD = "110",
        RISK_BLOCK_THRESHOLD = "150",
    }, nil, function()
        local ctx = {
            security = {
                client_ip = ip,
                risk = 80,
                block = true,
                waf_sqli = true,
                signals = {"waf_sqli"},
            },
        }

        risk_engine.run(ctx)

        check(ctx.security.risk_action == "block",
            "Out-of-range thresholds disabled risk block")

        check(kv["blacklist:" .. ip] == nil,
            "Invalid configuration issued an IP ban")
    end)
end)

run_case("P05 negative thresholds cannot downgrade WAF block", function()
    with_risk_env({
        RISK_LIMIT_THRESHOLD = "-5",
        RISK_BLOCK_THRESHOLD = "200",
    }, nil, function()
        local ctx = {
            security = {
                client_ip = ip,
                risk = 80,
                block = true,
                waf_sqli = true,
                signals = {"waf_sqli"},
            },
        }

        risk_engine.run(ctx)

        check(ctx.security.risk_action == "block",
            "Invalid threshold caused WAF block downgrade")
    end)
end)

run_case("P05 inverted thresholds cannot force low-score risk block", function()
    with_risk_env({
        RISK_LIMIT_THRESHOLD = "95",
        RISK_BLOCK_THRESHOLD = "20",
    }, nil, function()
        -- Isolate Risk Engine scoring: upstream block intentionally absent.
        local ctx = {
            security = {
                client_ip = ip,
                risk = 10,
                bad_bot_scanner = true,
                signals = {"bad_bot_scanner"},
            },
        }

        risk_engine.run(ctx)

        check(ctx.security.risk_action ~= "block"
            and ctx.security.risk_action ~= "limit",
            "Inverted thresholds caused incorrect risk mitigation")

        check(kv["blacklist:" .. ip] == nil,
            "Invalid threshold issued an IP ban")
    end)
end)

run_case("P05 invalid decay toggle must not silently disable decay", function()
    with_risk_env({
        RISK_DECAY_ENABLED = "ture",
        RISK_DECAY_FACTOR = "0.1",
    }, 1300, function()
        kv["risk:v1:" .. ip] = "50.00"
        kv["risk:v1:last_seen:" .. ip] = "1000"

        local ctx = {
            security = {
                client_ip = ip,
                risk = 20,
                bad_bot_scanner = true,
                signals = {"bad_bot_scanner"},
            },
        }

        risk_engine.run(ctx)

        check(
            math.abs(ctx.security.risk_final - 75) < 0.01,
            "Invalid decay toggle silently changed decay behavior"
        )
    end)
end)

-- ============================================================
-- Boundary and CAS exhaustion tests
-- ============================================================

run_case("P05 valid custom thresholds are preserved", function()
    with_risk_env({
        RISK_LIMIT_THRESHOLD = "40",
        RISK_BLOCK_THRESHOLD = "75",
    }, nil, function()

        -- 35 base + 10 scanner bonus = 45.
        -- Custom threshold=40 must produce LIMIT.
        local limited = {
            security = {
                client_ip = ip,
                risk = 35,
                bad_bot_scanner = true,
                signals = {"bad_bot_scanner"},
            },
        }

        risk_engine.run(limited)

        check(limited.security.risk_final == 45,
            "Unexpected score for custom threshold test")

        check(limited.security.risk_action == "limit",
            "Valid custom limit threshold was ignored")

        -- Different synthetic client to isolate reputation.
        -- 65 base + 10 scanner bonus = 75.
        local second_ip = "198.51.100.230"

        local blocked = {
            security = {
                client_ip = second_ip,
                risk = 65,
                bad_bot_scanner = true,
                signals = {"bad_bot_scanner"},
            },
        }

        risk_engine.run(blocked)

        check(blocked.security.risk_action == "block",
            "Valid custom block threshold was ignored")

        check(kv["blacklist:" .. second_ip] == nil,
            "Risk Engine created an unauthorized IP ban")
    end)
end)

run_case("P05 explicit false disables time decay", function()
    with_risk_env({
        RISK_LIMIT_THRESHOLD = "50",
        RISK_BLOCK_THRESHOLD = "80",
        RISK_DECAY_ENABLED = "false",
        RISK_DECAY_FACTOR = "0.1",
    }, 1300, function()

        kv["risk:v1:" .. ip] = "50.00"
        kv["risk:v1:last_seen:" .. ip] = "1000"

        local ctx = {
            security = {
                client_ip = ip,
                risk = 20,
                bad_bot_scanner = true,
                signals = {"bad_bot_scanner"},
            },
        }

        risk_engine.run(ctx)

        -- No decay: 50 existing + 20 base + 10 bonus = 80.
        check(ctx.security.risk_final == 80,
            "Explicit false unexpectedly applied decay")

        check(ctx.security.risk_action == "block",
            "Explicit false did not preserve full reputation")
    end)
end)

run_case("P05 CAS exhaustion preserves hard block without IP ban", function()
    -- Existing mock EVAL returns conflict while conflicts_left > 0.
    conflicts_left = 24

    local ctx = {
        security = {
            client_ip = ip,
            risk = 80,
            block = true,
            waf_sqli = true,
            signals = {"waf_sqli"},
        },
    }

    risk_engine.run(ctx)

    check(eval_calls == 24,
        "CAS retry bound was not respected")

    check(ctx.security.redis_risk_contention == true,
        "CAS exhaustion was not reported")

    check(ctx.security.block == true,
        "CAS exhaustion cleared an existing hard block")

    check(ctx.security.risk_action == "block",
        "CAS exhaustion downgraded the request decision")

    -- Mock conflict simulates another writer changing reputation.
    -- Check writes made by the tested engine separately.
    check(#writes == 0,
        "Exhausted CAS unexpectedly committed a write")

    check(kv["blacklist:" .. ip] == nil,
        "CAS exhaustion created an unauthorized IP ban")

    check(#alerts == 0,
        "CAS exhaustion generated an unconfirmed block alert")
end)

print(string.format("Risk Engine mock tests: %d passed, %d failed, %d total", passed, failed, passed + failed))
if failed > 0 then os.exit(1) end
