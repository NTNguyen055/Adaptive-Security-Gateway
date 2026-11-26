-- Bounded, observation-only security-event correlation.
--
-- Trust boundary:
--   * Input is constructed by security_shadow.log() from server-owned,
--     step-attributed security_signal_adapter observations.
--   * Remote address and request ID come from Nginx variables, never headers.
--   * Only WAF SQLi/XSS observations count here. They are preliminary evidence,
--     NOT verified exploits and NOT two independent detector sources.
--   * No automatic ban can be authorized without independently validated
--     exploit evidence AND a verified low-collateral NAT assessment.
--
-- Runtime storage: ngx.shared.security_correlator_cache (ephemeral, TTL-bounded).
-- No Redis, network, request blocking, session mutation or sensitive logging.
-- Lua 5.1 / LuaJIT compatible.

local M = {}

local WINDOW_SECONDS = 60
local LOOKBACK_WINDOWS = 5
local STATE_TTL = 360
local MIN_EVENTS = 8
local MIN_WINDOWS = 3
local MIN_CLASSES = 2

local function valid_ip_text(value)
    -- Syntax guard only. Canonicalization/trust comes from ngx.var.remote_addr.
    return type(value) == "string"
        and #value >= 3 and #value <= 45
        and value:match("^[0-9a-fA-F:.]+$") ~= nil
        and (value:find(".", 1, true) or value:find(":", 1, true))
end

local function valid_request_id(value)
    return type(value) == "string" and #value == 32
        and value:match("^[0-9a-fA-F]+$") ~= nil
end

local function classified_waf_event(trace)
    if type(trace) ~= "table"
        or type(trace.signals) ~= "table"
        or type(trace.errors) ~= "table"
        or type(trace.seen) ~= "table"
        or trace.pending ~= nil
        or trace.required_control_failed == true
        or #trace.errors > 0
        or trace.seen.waf_sqli_xss ~= true then
        return nil
    end

    local sqli, xss = false, false
    for _, item in ipairs(trace.signals) do
        if type(item) == "table" and item.source == "waf_sqli_xss" then
            if item.id == "waf_sqli" then sqli = true end
            if item.id == "waf_xss" then xss = true end
        end
    end

    -- Exactly one event and one class per HTTP request. A single payload
    -- producing both flags must not inflate event or class independence.
    if sqli then return "sqli" end
    if xss then return "xss" end
    return nil
end

local function counter(dict, key)
    local value = dict:get(key)
    if value == nil then return 0 end
    if type(value) ~= "number" or value < 0 then return nil end
    return value
end

local function counts(dict, identity, bucket)
    local event_count, window_count = 0, 0
    local class_seen = {sqli = false, xss = false}

    for offset = 0, LOOKBACK_WINDOWS - 1 do
        local prefix = "sc1:win:" .. identity .. ":" .. (bucket - offset)
        local n = counter(dict, prefix .. ":total")
        local sqli = counter(dict, prefix .. ":sqli")
        local xss = counter(dict, prefix .. ":xss")
        if not n or not sqli or not xss then return nil end
        if n > 0 then window_count = window_count + 1 end
        event_count = event_count + n
        if sqli > 0 then class_seen.sqli = true end
        if xss > 0 then class_seen.xss = true end
    end

    local class_count = (class_seen.sqli and 1 or 0)
        + (class_seen.xss and 1 or 0)
    return {
        event_count = event_count,
        distinct_windows = window_count,
        distinct_attack_classes = class_count,
    }
end

-- Called solely from the trusted Nginx shadow hook.
-- params: {trace=<adapter trace>, peer_ip=<ngx.var.remote_addr>,
--          request_id=<ngx.var.request_id>, partial=<bool>}
-- Result is observation metadata only; it is NOT a ban candidate.
function M.observe(params)
    if type(params) ~= "table" then return nil, "invalid_observation" end
    if params.partial == true then return {status = "SKIPPED_PARTIAL"} end

    local event_class = classified_waf_event(params.trace)
    if not event_class then return {status = "IGNORED"} end
    if not valid_ip_text(params.peer_ip)
        or not valid_request_id(params.request_id) then
        return nil, "untrusted_peer_or_request_id"
    end

    local ngx_api = ngx
    if type(ngx_api) ~= "table"
        or type(ngx_api.md5) ~= "function"
        or type(ngx_api.time) ~= "function"
        or type(ngx_api.shared) ~= "table" then
        return nil, "runtime_unavailable"
    end
    local dict = ngx_api.shared.security_correlator_cache
    if not dict or type(dict.add) ~= "function"
        or type(dict.incr) ~= "function"
        or type(dict.get) ~= "function" then
        return nil, "cache_unavailable"
    end

    local now = ngx_api.time()
    if type(now) ~= "number" or now < 0 then
        return nil, "invalid_clock"
    end
    local identity = ngx_api.md5(params.peer_ip)
    if type(identity) ~= "string" or not valid_request_id(identity) then
        return nil, "invalid_identity_hash"
    end

    local dedup_key = "sc1:seen:" .. identity .. ":" .. params.request_id
    local inserted, insert_err = dict:add(dedup_key, true, STATE_TTL)
    if not inserted then
        if insert_err == "exists" then return {status = "DUPLICATE"} end
        return nil, "cache_write_failed"
    end

    local bucket = math.floor(now / WINDOW_SECONDS)
    local prefix = "sc1:win:" .. identity .. ":" .. bucket
    local total = dict:incr(prefix .. ":total", 1, 0, STATE_TTL)
    local classes = dict:incr(prefix .. ":" .. event_class, 1, 0, STATE_TTL)
    if not total or not classes then return nil, "cache_write_failed" end

    local summary = counts(dict, identity, bucket)
    if not summary then return nil, "cache_read_failed" end

    -- Strong WAF patterns still lack independent detection sources and a
    -- trustworthy low-collateral assessment of NAT/CGNAT membership.
    local suspicious = summary.event_count >= MIN_EVENTS
        and summary.distinct_windows >= MIN_WINDOWS
        and summary.distinct_attack_classes >= MIN_CLASSES

    local notify = false
    if suspicious then
        local claimed = dict:add("sc1:notice:" .. identity, true, STATE_TTL)
        notify = claimed == true
    end

    summary.status = suspicious and "SUSPICIOUS_SHADOW" or "OBSERVED"
    summary.notify = notify
    summary.independent_sources_verified = false
    summary.nat_assessment = "unknown"
    summary.auto_ban_eligible = false
    return summary
end

-- Used by ip_ban_issuer.lua as an authorization boundary. Observation-derived
-- counters are NOT proof of confirmed exploits or safe IP attribution.
-- Even an input with forged approved/verified fields cannot enable issuance.
-- A future verified correlator must replace this deliberately closed contract
-- only after independently sourced evidence and NAT assessment exist.
function M.verify(_incident)
    return nil, "independent_evidence_and_nat_assessment_unavailable"
end

M.WINDOW_SECONDS = WINDOW_SECONDS
M.LOOKBACK_WINDOWS = LOOKBACK_WINDOWS
M.STATE_TTL = STATE_TTL
return M
