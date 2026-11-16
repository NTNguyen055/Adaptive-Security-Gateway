-- Bounded-cardinality labels for Prometheus security metrics.
-- Keep high-cardinality client identifiers in logs, never in metric labels.
local _M = {}

local REASON_PRIORITY = {
    "ip_blacklist_manual", "ip_blacklist_auto", "ip_blacklist_cached", "ip_blacklist",
    "waf_sqli", "waf_xss", "brute_force_attack",
    "jwt_alg_attack", "jwt_replay", "jwt_missing", "jwt_invalid",
    "rate_limit_hard", "rate_limit_burst", "redis_rate_exceeded",
    "bad_bot_scanner", "bad_bot_headless", "xff_spoof", "xff_chain_abuse",
    "xff_malformed", "xff_private_chain", "geo_block",
}

function _M.action(value)
    if value == "block" or value == "limit" then return value end
    return "pass"
end

function _M.reason(signals, action)
    local present = {}
    if type(signals) == "table" then
        for _, raw in ipairs(signals) do
            if type(raw) == "string" then
                local prefix = raw:match("^([^:]+)")
                if prefix then present[prefix] = true end
            end
        end
    end
    for _, key in ipairs(REASON_PRIORITY) do
        if present[key] then return key end
    end
    if action == "limit" then return "risk_limit" end
    if action == "block" then return "risk_block" end
    return "other"
end

return _M
