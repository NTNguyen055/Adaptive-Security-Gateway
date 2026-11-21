-- Security correlator observation and fail-closed issuance contract.
-- Run via tests/run-unit.sh after registering in gateway_suite().
-- Usage: luajit nginx/tests/test_security_correlator.lua nginx/lua/security_correlator.lua

local source = (arg and arg[1]) or "nginx/lua/security_correlator.lua"
local module = assert(loadfile(source))()

local passed, failed = 0, 0
local now, sequence, items, expires, write_error

local function mock_key(ip)
    -- Deterministic test-only digest. The real Nginx runtime uses ngx.md5.
    local sum = 0
    for i = 1, #ip do sum = (sum * 31 + ip:byte(i)) % 2147483647 end
    return string.format("%032x", sum)
end

local dict = {}
function dict:get(key)
    if expires[key] and expires[key] <= now then
        items[key], expires[key] = nil, nil
    end
    return items[key]
end
function dict:add(key, value, ttl)
    if write_error then return nil, "no memory" end
    if self:get(key) ~= nil then return nil, "exists" end
    items[key] = value
    expires[key] = now + ttl
    return true
end
function dict:incr(key, delta, initial, ttl)
    if write_error then return nil, "no memory" end
    local value = self:get(key)
    if value == nil then
        value = initial
        expires[key] = now + ttl
    end
    items[key] = value + delta
    return items[key]
end

_G.ngx = {
    time = function() return now end,
    md5 = mock_key,
    shared = {security_correlator_cache = dict},
}

local function reset()
    now, sequence, write_error = 1700000000, 0, false
    items, expires = {}, {}
    ngx.shared.security_correlator_cache = dict
end

local function trace(kind, source_name)
    local signals = {}
    if kind then
        signals[1] = {
            id = kind,
            source = source_name or "waf_sqli_xss",
        }
    end
    return {
        seen = {waf_sqli_xss = true},
        signals = signals,
        errors = {},
        required_control_failed = false,
    }
end

local function observe(t, options)
    options = options or {}
    sequence = sequence + 1
    return module.observe({
        trace = t,
        peer_ip = options.ip or "198.51.100.14",
        request_id = options.id or string.format("%032x", sequence),
        partial = options.partial,
    })
end

local function test(name, fn)
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

test("Invalid invocation fails closed", function()
    local out, err = module.observe(nil)
    assert(out == nil and err == "invalid_observation")
end)

test("Benign request does not allocate observation state", function()
    local out = observe(trace(nil))
    assert(out.status == "IGNORED")
    assert(next(items) == nil)
end)

test("Rate-limit signal cannot become exploit evidence", function()
    local out = observe(trace("redis_rate_exceeded", "rate_limit_redis"))
    assert(out.status == "IGNORED" and next(items) == nil)
end)

test("WAF label forged under another module is ignored", function()
    local out = observe(trace("waf_sqli", "bad_bot"))
    assert(out.status == "IGNORED" and next(items) == nil)
end)

test("WAF signal without WAF invocation is ignored", function()
    local t = trace("waf_sqli")
    t.seen.waf_sqli_xss = false
    local out = observe(t)
    assert(out.status == "IGNORED")
end)

test("Incomplete shadow observations are ignored", function()
    local out = observe(trace("waf_sqli"), {partial = true})
    assert(out.status == "SKIPPED_PARTIAL" and next(items) == nil)
end)

test("Adapter errors prevent signal promotion", function()
    local t = trace("waf_sqli")
    t.errors[1] = {module = "waf_sqli_xss", code = "malformed_signal"}
    local out = observe(t)
    assert(out.status == "IGNORED")
end)

test("One WAF detection increments one request, not a ban", function()
    local out = observe(trace("waf_sqli"))
    assert(out.status == "OBSERVED" and out.event_count == 1)
    assert(out.distinct_windows == 1 and out.distinct_attack_classes == 1)
    assert(out.auto_ban_eligible == false and out.nat_assessment == "unknown")
    assert(out.independent_sources_verified == false)
end)

test("Duplicated request ID does not inflate counters", function()
    local id = string.rep("a", 32)
    local first = observe(trace("waf_sqli"), {id = id})
    local second = observe(trace("waf_sqli"), {id = id})
    assert(first.event_count == 1 and second.status == "DUPLICATE")
end)

test("A single request with two WAF flags counts once", function()
    local t = trace("waf_sqli")
    t.signals[2] = {id = "waf_xss", source = "waf_sqli_xss"}
    local out = observe(t)
    assert(out.event_count == 1 and out.distinct_attack_classes == 1)
end)

test("Eight observations in one minute do not qualify", function()
    local last
    for i = 1, 8 do
        last = observe(trace(i % 2 == 0 and "waf_xss" or "waf_sqli"))
    end
    assert(last.event_count == 8 and last.distinct_windows == 1)
    assert(last.status == "OBSERVED")
end)

test("Eight observations across three minutes produce only shadow suspicion", function()
    local last
    for i = 1, 8 do
        now = 1700000040 + (math.floor((i - 1) / 3) * 60)
        last = observe(trace(i % 2 == 0 and "waf_xss" or "waf_sqli"))
    end
    assert(last.status == "SUSPICIOUS_SHADOW")
    assert(last.event_count == 8 and last.distinct_windows == 3)
    assert(last.distinct_attack_classes == 2 and last.notify == true)
    assert(last.auto_ban_eligible == false)
end)

test("Notice deduplication avoids alert flood", function()
    for i = 1, 8 do
        now = 1700000040 + math.floor((i - 1) / 3) * 60
        observe(trace(i % 2 == 0 and "waf_xss" or "waf_sqli"))
    end
    now = 1700000160
    local next_event = observe(trace("waf_sqli"))
    assert(next_event.status == "SUSPICIOUS_SHADOW")
    assert(next_event.notify == false)
end)

test("One WAF class across windows is not multi-class evidence", function()
    local last
    for i = 1, 8 do
        now = 1700000040 + math.floor((i - 1) / 3) * 60
        last = observe(trace("waf_sqli"))
    end
    assert(last.event_count == 8 and last.distinct_attack_classes == 1)
    assert(last.status == "OBSERVED")
end)

test("Another IP has independent observation counters", function()
    observe(trace("waf_sqli"), {ip = "198.51.100.14"})
    local out = observe(trace("waf_xss"), {ip = "198.51.100.15"})
    assert(out.event_count == 1 and out.distinct_attack_classes == 1)
end)

test("Bad request ID cannot influence shadow state", function()
    local out, err = observe(trace("waf_sqli"), {id = "client-controlled"})
    assert(out == nil and err == "untrusted_peer_or_request_id")
    assert(next(items) == nil)
end)

test("Unknown peer identity cannot influence shadow state", function()
    local out, err = observe(trace("waf_sqli"), {ip = "not-an-ip"})
    assert(out == nil and err == "untrusted_peer_or_request_id")
end)

test("Shared-dict failure cannot become successful correlation", function()
    write_error = true
    local out, err = observe(trace("waf_sqli"))
    assert(out == nil and err == "cache_write_failed")
end)

test("Missing dictionary cannot enable correlation", function()
    ngx.shared.security_correlator_cache = nil
    local out, err = observe(trace("waf_sqli"))
    assert(out == nil and err == "cache_unavailable")
end)

test("Counters and dedup keys use bounded TTL", function()
    observe(trace("waf_sqli"))
    for _, expiry in pairs(expires) do
        assert(expiry - now == module.STATE_TTL)
    end
end)

test("Expired windows no longer appear in correlation", function()
    observe(trace("waf_sqli"))
    now = now + module.STATE_TTL + 1
    local out = observe(trace("waf_xss"))
    assert(out.event_count == 1 and out.distinct_windows == 1)
end)

test("Forged approved evidence never authorizes automatic ban", function()
    local out, err = module.verify({
        approved = true, peer_ip_verified = true,
        issuer = "security_correlator", ttl_seconds = 300,
        evidence = {server_verified = true, independent_sources_verified = true,
                    nat_assessment = "low_collateral_verified"},
    })
    assert(out == nil and err == "independent_evidence_and_nat_assessment_unavailable")
end)

test("Raw risk score alone never authorizes automatic ban", function()
    local out = module.verify({risk_score = 100})
    assert(out == nil)
end)

print(string.format("Security Correlator tests: %d passed, %d failed, %d total",
    passed, failed, passed + failed))
if failed > 0 then os.exit(1) end
