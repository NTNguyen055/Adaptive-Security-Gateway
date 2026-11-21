-- Authorized temporary IP-ban issuance.
--
-- This module is an internal writer, not a request handler.
-- It NEVER accepts an authorization decision as a bearer capability.
-- A trusted, server-side security_correlator must VERIFY evidence and build
-- the candidate; absent that module, issuance is disabled (fail closed).
--
-- One Redis key stores both enforcement state and its bounded audit metadata.
-- No blacklist:<ip> or blacklist_ips writes are performed here.
-- Lua 5.1 / LuaJIT compatible.

local M = {}
local redis_helper = require "redis_helper"
local authorizer = require "ip_ban_authorizer"

local ISSUE_SCRIPT = [[
local key = KEYS[1]
local ip = ARGV[1]
local incident = ARGV[2]
local ttl = tonumber(ARGV[3])

if type(ip) ~= 'string' or #ip < 3 or #ip > 45
    or not string.match(ip, '^[0-9a-fA-F:.]+$')
    or type(incident) ~= 'string'
    or not string.match(incident, '^[0-9a-f]+$')
    or #incident < 16 or #incident > 64
    or not ttl or ttl % 1 ~= 0 or ttl < 1 or ttl > 300
    or key ~= 'ban:v2:ip:' .. ip then
    return redis.error_reply('invalid authorized ban arguments')
end

local key_type = redis.call('TYPE', key).ok
if key_type ~= 'none' and key_type ~= 'string' then
    return redis.error_reply('invalid ban key type')
end

-- A pre-existing ban is never silently prolonged or overwritten.
if redis.call('EXISTS', key) == 1 then return 0 end

local now = tonumber(redis.call('TIME')[1])
local record = cjson.encode({
    schema = 1,
    scope = 'ip',
    ip = ip,
    issuer = 'security_correlator',
    reason = 'confirmed_exploit_campaign',
    incident_id = incident,
    issued_at = now,
    expires_at = now + ttl,
    ttl_seconds = ttl
})

-- Atomic SET NX EX: enforcement and its provenance are one value.
local committed = redis.call('SET', key, record, 'NX', 'EX', ttl)
if not committed then return 0 end
return 1
]]

local function discard_connection(red)
    if red and type(red.close) == "function" then
        pcall(function() red:close() end)
    end
end

local function notify_l1(ip)
    -- Invalidate negative cache on THIS gateway. Other gateways retain
    -- their bounded (5-second) negative-cache visibility delay.
    local cache = ngx and ngx.shared and ngx.shared.ip_cache
    if cache and type(cache.delete) == "function" then
        pcall(function() cache:delete("bl:" .. ip) end)
    end
end

local function audit(level, code, ip, incident, ttl)
    if ngx and ngx.log then
        ngx.log(level, "[AUTHORIZED_BAN] outcome=", code,
            " ip=", tostring(ip or "unknown"),
            " incident=", tostring(incident or "none"),
            " ttl=", tostring(ttl or 0))
    end
end

-- The current security_correlator is shadow-only.
-- Unverified observations cannot authorize automatic IP bans.
-- Future issuance requires independently verified evidence
-- and trustworthy NAT collateral-impact assessment.
function M.issue_verified(incident)
    local ok_load, correlator = pcall(require, "security_correlator")
    if not ok_load
        or type(correlator) ~= "table"
        or type(correlator.verify) ~= "function" then
        return nil, "trusted_correlator_unavailable"
    end

    local ok_verify, candidate = pcall(correlator.verify, incident)
    if not ok_verify or type(candidate) ~= "table" then
        return nil, "correlation_not_verified"
    end

    -- Do not trust candidate.approved, TTL, reason or peer-IP claims
    -- as already-authorized. Re-run the policy here at the writer boundary.
    local decision, policy_err = authorizer.authorize(candidate)
    if not decision then
        return nil, "ban_policy_error:" .. tostring(policy_err)
    end
    if decision.approved ~= true or decision.action ~= "AUTHORIZE_TEMP_IP_BAN" then
        return nil, "ban_policy_denied:" .. tostring(decision.reason)
    end

    local ip = candidate.ip
    local ttl = decision.ttl_seconds
    local incident_id = decision.incident_id
    local red, conn_err = redis_helper.get_redis(0)
    if not red then
        audit(ngx.ERR, "REDIS_UNAVAILABLE", ip, incident_id, ttl)
        return nil, "ban_storage_unavailable:" .. tostring(conn_err)
    end

    local result, eval_err = red:eval(
        ISSUE_SCRIPT, 1, "ban:v2:ip:" .. ip, ip, incident_id, ttl
    )

    if result ~= 0 and result ~= 1 then
        discard_connection(red)
        audit(ngx.ERR, "WRITE_ERROR", ip, incident_id, ttl)
        return nil, "ban_storage_unconfirmed:" .. tostring(eval_err)
    end

    redis_helper.close(red)
    if result == 0 then
        return {
            status = "ALREADY_ACTIVE",
            ip = ip,
            incident_id = incident_id,
        }
    end

    notify_l1(ip)
    audit(ngx.WARN, "ISSUED", ip, incident_id, ttl)
    return {
        status = "ISSUED",
        ip = ip,
        incident_id = incident_id,
        ttl_seconds = ttl,
    }
end

return M
