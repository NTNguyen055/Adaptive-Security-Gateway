-- P0.2.4-A: Unified Security Decision Policy (pure Lua; not wired into nginx.conf).
-- IMPORTANT: This module makes REQUEST decisions only. It NEVER creates Redis IP bans.
-- Signals and ban verdicts MUST come from trusted server-side modules, never headers.
-- Compatible with LuaJIT / Lua 5.1; no ngx, Redis, network, or mutable global state.

local M = {}

-- Canonical signal IDs and their trusted in-process producers.
-- A new detector must be registered and contract-tested before enforcement.
local SOURCE = {
    waf_sqli = "waf_sqli_xss",
    waf_xss = "waf_sqli_xss",
    bad_bot_scanner = "bad_bot",
    bad_bot_headless = "bad_bot",
    empty_ua = "bad_bot",
    ua_unknown = "bad_bot",
    dev_tool = "bad_bot",
    xff_chain_abuse = "xff_guard",
    xff_spoof = "xff_guard",
    xff_malformed = "xff_guard",
    xff_private_chain = "xff_guard",
    geo_block = "geo_block",
    geo_unknown = "geo_block",
    jwt_missing = "jwt_auth",
    jwt_malformed = "jwt_auth",
    jwt_invalid = "jwt_auth",
    jwt_blocked_cache = "jwt_auth",
    jwt_alg_attack = "jwt_auth",
    jwt_payload_invalid = "jwt_auth",
    jwt_no_exp = "jwt_auth",
    jwt_expired = "jwt_auth",
    jwt_nbf = "jwt_auth",
    jwt_iat_future = "jwt_auth",
    jwt_replay = "jwt_auth",       -- Existing code uses IP mismatch as this signal.
    jwt_ip_changed = "jwt_auth",   -- Future explicit, less accusatory signal.
    rate_limit_hard = "rate_limit",
    rate_limit_burst = "rate_limit",
    redis_rate_exceeded = "rate_limit_redis",
    redis_rate_warn = "rate_limit_redis",
    brute_force_attack = "brute_force_login", -- Legacy signal, to migrate.
    auth_account_backoff = "login_accounting", -- Future V3 signal.
    ml_anomaly = "ml_detector",    -- Observe-only until calibrated and verified.
    ip_blacklist_manual = "ip_blacklist",
    ip_blacklist_auto = "ip_blacklist",
    ip_blacklist_cached = "ip_blacklist",
}

local function decision(action, status, scope, reason)
    return {
        action = action,
        http_status = status, -- nil means forward normally.
        scope = scope,
        reason = reason,
        create_ip_ban = false, -- An IP-ban writer is a separate, audited component.
    }
end

local function first_present(present, candidates)
    -- Deterministic order: do not use pairs() for selecting the reason code.
    for _, name in ipairs(candidates) do
        if present[name] then return name end
    end
    return nil
end

local AUTH_ORDER = {
    "jwt_alg_attack", "jwt_invalid", "jwt_blocked_cache", "jwt_malformed",
    "jwt_payload_invalid", "jwt_no_exp", "jwt_expired", "jwt_nbf",
    "jwt_iat_future", "jwt_missing",
}
local BLOCK_ORDER = {
    "waf_sqli", "waf_xss", "xff_chain_abuse", "geo_block",
    "bad_bot_scanner", "brute_force_attack", "ip_blacklist_manual",
    "ip_blacklist_auto", "ip_blacklist_cached",
}
local LIMIT_ORDER = {
    "rate_limit_hard", "rate_limit_burst", "redis_rate_exceeded",
    "bad_bot_headless",
}

-- Input is produced by a trusted in-process adapter; source strings are NOT
-- cryptographic attestations. Never pass HTTP headers or client JSON into it.
-- The caller MUST handle (nil, error) as UNAVAILABLE, never as ALLOW.
local MAX_SIGNALS = 64
local MAX_NAME_LENGTH = 64
local function valid_name(value)
    return type(value) == "string" and #value > 0
        and #value <= MAX_NAME_LENGTH
        and value:match("^[a-z][a-z0-9_]*$") ~= nil
end

local function valid_bool(value)
    return value == nil or type(value) == "boolean"
end

local function validate_signals(signals)
    if type(signals) ~= "table" then return nil, "invalid_signals" end

    local count = 0
    local highest = 0
    -- pairs() catches sparse, mixed-key or map-style tables that ipairs()
    -- would silently skip. Bound before parsing to limit per-request CPU.
    for key in pairs(signals) do
        if type(key) ~= "number" or key < 1 or key % 1 ~= 0 then
            return nil, "invalid_signal_array"
        end
        count = count + 1
        if count > MAX_SIGNALS then return nil, "too_many_signals" end
        if key > highest then highest = key end
    end
    if highest ~= count then return nil, "invalid_signal_array" end

    local present = {}
    for i = 1, count do
        local event = signals[i]
        if type(event) ~= "table" or not valid_name(event.id)
            or not valid_name(event.source) then
            return nil, "invalid_signal_at_" .. tostring(i)
        end
        local expected = SOURCE[event.id]
        if expected and event.source ~= expected then
            return nil, "invalid_signal_source:" .. event.id
        end
        -- Unknown signals may be logged, but cannot activate enforcement.
        present[event.id] = true
    end
    return present, count
end

function M.evaluate(input)
    if type(input) ~= "table" then return nil, "invalid_input" end
    if not valid_bool(input.required_control_failed)
        or not valid_bool(input.jwt_required)
        or not valid_bool(input.account_restricted)
        or not valid_bool(input.legacy_blocked)
        or not valid_bool(input.legacy_rate_only) then
        return nil, "invalid_boolean_field"
    end
    if input.jwt_status ~= nil
        and input.jwt_status ~= "verified"
        and input.jwt_status ~= "missing"
        and input.jwt_status ~= "invalid"
        and input.jwt_status ~= "ip_changed"
        and input.jwt_status ~= "error" then
        return nil, "invalid_jwt_status"
    end
    if input.risk_score ~= nil then
        local score = input.risk_score
        if type(score) ~= "number" or score ~= score or score < 0
            or score > 100 then
            return nil, "invalid_risk_score"
        end
    end

    local present, count_or_error = validate_signals(input.signals or {})
    if not present then return nil, count_or_error end
    local has_any_signal = count_or_error > 0

    if input.required_control_failed == true then
        return decision("UNAVAILABLE", 503, "request", "required_security_control_failed")
    end

    local ban = input.ip_ban
    if ban ~= nil then
        if type(ban) ~= "table" or type(ban.active) ~= "boolean" then
            return nil, "invalid_ip_ban_verdict"
        end
        if ban.active then
            if ban.verified ~= true or (ban.origin ~= "manual" and ban.origin ~= "automatic") then
                return nil, "unverified_ip_ban"
            end
            return decision("DENY_IP", 403, "ip", "ip_blacklist_" .. ban.origin)
        end
    end

    -- No protected request may pass merely because the JWT module emitted no signal.
    -- The gateway adapter must supply jwt_status from successful server-side verification.
    if input.jwt_required == true then
        local status = input.jwt_status
        if status == nil or status == "error" then
            return decision("UNAVAILABLE", 503, "request", "jwt_verification_unavailable")
        end
        local jwt_reason = first_present(present, AUTH_ORDER)
        if jwt_reason or status == "missing" or status == "invalid" then
            return decision("BLOCK_REQUEST", 403, "request", jwt_reason or "jwt_denied")
        end
        if present.jwt_replay or present.jwt_ip_changed or status == "ip_changed" then
            -- An IP change is not proof that the source IP is malicious.
            return decision("REAUTH_SESSION", 401, "session", "jwt_ip_binding_changed")
        end
    end

    -- Auth denial is mandatory whenever the trusted JWT detector reported it,
    -- even if the route configuration says JWT is not normally required.
    local auth_reason = first_present(present, AUTH_ORDER)
    if auth_reason then
        return decision("BLOCK_REQUEST", 403, "request", auth_reason)
    end
    if present.jwt_replay or present.jwt_ip_changed then
        return decision("REAUTH_SESSION", 401, "session", "jwt_ip_binding_changed")
    end

    local attack_reason = first_present(present, BLOCK_ORDER)
    if attack_reason then
        return decision("BLOCK_REQUEST", 403, "request", attack_reason)
    end

    -- Adapter only marks legacy_blocked for NON-rate detector denials.
    -- It is never safe to downgrade an otherwise-unmapped security block.
    local limit_reason = first_present(present, LIMIT_ORDER)
    if input.legacy_blocked == true then
        return decision("BLOCK_REQUEST", 403, "request", "unmapped_detector_block")
    end

    if input.account_restricted == true or present.auth_account_backoff then
        return decision("ACCOUNT_RESTRICT", 429, "account", "auth_account_backoff")
    end

    if limit_reason then
        return decision("THROTTLE", 429, "request", limit_reason)
    end

    if has_any_signal or (input.risk_score or 0) > 0 then
        return decision("OBSERVE", nil, "request", "context_or_unconfirmed_signal")
    end
    return decision("ALLOW", nil, "request", "no_security_signal")
end

return M
