-- Stage 1.4: bounded auto bans and explicit persistent manual bans.
-- Persistent manual bans live in the blacklist_ips SET.
-- Temporary automatic bans live in blacklist:<ip> (EX TTL).
-- IMPORTANT migration: older Risk Engine versions also wrote auto bans to
-- blacklist_ips. Audit/migrate legacy SET members before production rollout.
local _M = {}
local redis_helper = require "redis_helper"

local CACHE_TTL_POSITIVE = 60
-- Bound the delay before a newly issued manual ban becomes visible.
-- Reduced from 30s to 5s; immediate enforcement needs explicit cache
-- invalidation through a privileged ban-management workflow (Stage 1.5 follow-up).
local CACHE_TTL_NEGATIVE = 5

local function block_request(ctx, ip, reason)
    ctx.security.ip_blacklisted = true
    ctx.security.block = true
    ctx.security.risk = 100
    ctx.security.signals[#ctx.security.signals + 1] = reason
    ngx.log(ngx.WARN, "[BLACKLIST] blocked ip=", ip, " reason=", reason)
    -- Do not increment metric_blocked here: security_alert() records the
    -- final HTTP decision, and incrementing here would count it twice.
end

local function valid_replies(results)
    if type(results) ~= "table" or #results ~= 2 then return false end
    if results[1] ~= 0 and results[1] ~= 1 then return false end
    local key_reply = results[2]
    return key_reply == ngx.null or key_reply == "1" or key_reply == "0"
end

local function discard_connection(red)
    if red and type(red.close) == "function" then
        pcall(function() red:close() end)
    end
end

function _M.run(ctx)
    ctx.security = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}
    local ip = ctx.security.client_ip
        or ngx.var.remote_addr or ngx.var.realip_remote_addr
    if not ip then return end

    local cache = ngx.shared and ngx.shared.ip_cache
    local cache_key = "bl:" .. ip
    local cached = cache and cache:get(cache_key) or nil

    -- Negative hits are a bounded 5-second trade-off: a newly added manual
    -- ban might not take effect until the negative cache expires.
    if cached == 0 then return end

    -- Positive hits are revalidated every time to honor manual unban and
    -- automatic TTL expiry without waiting for the L1 cache to expire.
    local red, err = redis_helper.get_redis(0)
    if not red then
        ngx.log(ngx.WARN, "[BLACKLIST] Redis unavailable: ", tostring(err))
        ctx.security.redis_bl_fail = true
        -- Fail closed only for an IP previously confirmed blacklisted in L1.
        -- Cache misses fail open for THIS module; other security layers run.
        if cached == 1 then block_request(ctx, ip, "ip_blacklist_cached") end
        return
    end

    red:init_pipeline()
    red:sismember("blacklist_ips", ip)
    red:get("blacklist:" .. ip)
    local results, pipe_err = red:commit_pipeline()
    if not results or not valid_replies(results) then
        discard_connection(red)
        ctx.security.redis_bl_error = true
        ngx.log(ngx.ERR, "[BLACKLIST] Invalid pipeline replies: ", tostring(pipe_err))
        if cached == 1 then block_request(ctx, ip, "ip_blacklist_cached") end
        return
    end
    redis_helper.close(red)

    local is_manual = results[1] == 1
    local is_automatic = results[2] == "1"
    if is_manual or is_automatic then
        if cache then cache:set(cache_key, 1, CACHE_TTL_POSITIVE) end
        block_request(ctx, ip, is_manual and "ip_blacklist_manual" or "ip_blacklist_auto")
        return
    end

    if cache then cache:set(cache_key, 0, CACHE_TTL_NEGATIVE) end
end

return _M
