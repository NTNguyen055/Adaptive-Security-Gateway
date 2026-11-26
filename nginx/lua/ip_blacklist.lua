-- Read-only IP-ban enforcement across three isolated authorities.
-- 1. Persistent manual ban: blacklist_ips SET.
-- 2. Authorized temporary ban: ban:v2:ip:<ip> with verified provenance/TTL.
-- 3. Legacy temporary ban: blacklist:<ip>, kept for safe migration.
--
-- Never create bans from request risk, login failures, or cache state.
-- Data migration is audit-only; no unreviewed Redis deletion.

local M = {}
local redis_helper = require "redis_helper"
local cjson = require "cjson.safe"

local CACHE_TTL_POSITIVE = 60
local CACHE_TTL_NEGATIVE = 5
local MAX_AUTHORIZED_TTL_MS = 300000

local function block_request(ctx, ip, reason, origin)
    ctx.security.ip_blacklisted = true
    ctx.security.block = true
    ctx.security.risk = 100
    ctx.security.ban_origin = origin
    ctx.security.signals[#ctx.security.signals + 1] = reason
    ngx.log(ngx.WARN, "[BLACKLIST] blocked ip=", ip,
        " origin=", origin, " reason=", reason)
end

local function discard_connection(red)
    if red and type(red.close) == "function" then
        pcall(function() red:close() end)
    end
end

local function valid_replies(results)
    if type(results) ~= "table" or #results ~= 4 then return false end
    if results[1] ~= 0 and results[1] ~= 1 then return false end
    if results[2] ~= ngx.null
        and results[2] ~= "1"
        and results[2] ~= "0" then return false end
    if results[3] ~= ngx.null and type(results[3]) ~= "string" then
        return false
    end
    if type(results[4]) ~= "number" then return false end
    return true
end

local function valid_authorized_record(value, pttl_ms, ip)
    if value == ngx.null then
        -- A missing key must have PTTL=-2. A mismatch is a Redis snapshot
        -- race (e.g. expiry between commands), not proof of a ban.
        return false
    end

    if type(value) ~= "string" or #value > 1024
        or pttl_ms <= 0 or pttl_ms > MAX_AUTHORIZED_TTL_MS then
        return false
    end

    local data = cjson.decode(value)
    if type(data) ~= "table"
        or data.schema ~= 1
        or data.scope ~= "ip"
        or data.ip ~= ip
        or data.issuer ~= "security_correlator"
        or data.reason ~= "confirmed_exploit_campaign"
        or type(data.incident_id) ~= "string"
        or #data.incident_id < 16
        or #data.incident_id > 64
        or not data.incident_id:match("^[a-f0-9]+$")
        or type(data.issued_at) ~= "number"
        or type(data.expires_at) ~= "number"
        or type(data.ttl_seconds) ~= "number"
        or data.ttl_seconds % 1 ~= 0
        or data.ttl_seconds < 1
        or data.ttl_seconds > 300
        or data.expires_at - data.issued_at ~= data.ttl_seconds then
        return false
    end

    return true
end

function M.run(ctx)
    ctx.security = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    local ip = ctx.security.client_ip
        or ngx.var.remote_addr or ngx.var.realip_remote_addr
    if not ip or ip == "" then return end

    local cache = ngx.shared and ngx.shared.ip_cache
    local cache_key = "bl:" .. ip
    local cached = cache and cache:get(cache_key) or nil

    -- Negative cache can delay new bans by at most 5s across gateways.
    if cached == 0 then return end

    -- Positive cache is revalidated to respect manual unban and expiry.
    local red, err = redis_helper.get_redis(0)
    if not red then
        ctx.security.redis_bl_fail = true
        ngx.log(ngx.WARN, "[BLACKLIST] Redis unavailable: ", tostring(err))
        if cached == 1 then
            block_request(ctx, ip, "ip_blacklist_cached", "cached_unverified")
        end
        return
    end

    red:init_pipeline()
    red:sismember("blacklist_ips", ip)
    red:get("blacklist:" .. ip)
    red:get("ban:v2:ip:" .. ip)
    red:pttl("ban:v2:ip:" .. ip)
    local results, pipe_err = red:commit_pipeline()

    if not valid_replies(results) then
        discard_connection(red)
        ctx.security.redis_bl_error = true
        ngx.log(ngx.ERR, "[BLACKLIST] Invalid Redis pipeline: ",
            tostring(pipe_err))
        if cached == 1 then
            block_request(ctx, ip, "ip_blacklist_cached", "cached_unverified")
        end
        return
    end
    redis_helper.close(red)

    local manual = results[1] == 1
    local legacy = results[2] == "1"
    local authorized = valid_authorized_record(results[3], results[4], ip)

    if results[3] ~= ngx.null and not authorized then
        -- Malformed/indefinite authorized records cannot create an IP ban.
        ctx.security.redis_bl_error = true
        ngx.log(ngx.ERR,
            "[BLACKLIST] Invalid authorized-ban record for ip=", ip)
    end

    if manual or authorized or legacy then
        if cache then cache:set(cache_key, 1, CACHE_TTL_POSITIVE) end
        if manual then
            block_request(ctx, ip, "ip_blacklist_manual", "manual")
        elseif authorized then
            block_request(ctx, ip, "ip_blacklist_auto", "authorized_v2")
        else
            block_request(ctx, ip, "ip_blacklist_auto", "legacy")
        end
        return
    end

    -- Do not negative-cache a malformed authorized record.
    if cache and not ctx.security.redis_bl_error then
        cache:set(cache_key, 0, CACHE_TTL_NEGATIVE)
    end
end

return M
