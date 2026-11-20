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
    "bad_bot_scanner", "brute_force_attack",
}
local LIMIT_ORDER = {
    "rate_limit_hard", "rate_limit_burst", "redis_rate_exceeded",
    "bad_bot_headless",
}

-- Input:
--   {
--      signals = {{id='waf_sqli', source='waf_sqli_xss'}, ...},
--      required_control_failed = false,
--      ip_ban = {active=true, verified=true, origin='manual'|'automatic'},
--      jwt_required = false,
--      jwt_status = "verified"|"missing"|"invalid"|"ip_changed"|"error",
--      account_restricted = false,
--      risk_score = 0..100, -- telemetry only; NEVER a ban authorization.
--   }
-- The caller MUST treat nil,error as a security-control failure, not ALLOW.
function M.evaluate(input)
    if type(input) ~= "table" then return nil, "invalid_input" end
    local signals = input.signals or {}
    if type(signals) ~= "table" then return nil, "invalid_signals" end
    if input.risk_score ~= nil then
        local score = input.risk_score
        if type(score) ~= "number" or score ~= score or score < 0 or score > 100 then
            return nil, "invalid_risk_score"
        end
    end

    local present = {}
    local has_any_signal = false
    for i, event in ipairs(signals) do
        if type(event) ~= "table" or type(event.id) ~= "string"
            or type(event.source) ~= "string" then
            return nil, "invalid_signal_at_" .. tostring(i)
        end
        local expected = SOURCE[event.id]
        if expected and event.source ~= expected then
            return nil, "invalid_signal_source:" .. event.id
        end
        -- Unknown signals are observable only; never silently gain enforcement.
        present[event.id] = true
        has_any_signal = true
    end

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
        if status ~= "verified" and status ~= "missing"
            and status ~= "invalid" and status ~= "ip_changed" then
            return nil, "invalid_jwt_status"
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

    local attack_reason = first_present(present, BLOCK_ORDER)
    if attack_reason then
        return decision("BLOCK_REQUEST", 403, "request", attack_reason)
    end

    if input.account_restricted == true or present.auth_account_backoff then
        return decision("ACCOUNT_RESTRICT", 429, "account", "auth_account_backoff")
    end

    local limit_reason = first_present(present, LIMIT_ORDER)
    if limit_reason then
        return decision("THROTTLE", 429, "request", limit_reason)
    end

    if has_any_signal or (input.risk_score or 0) > 0 then
        return decision("OBSERVE", nil, "request", "context_or_unconfirmed_signal")
    end
    return decision("ALLOW", nil, "request", "no_security_signal")
end

return M
