-- P0.2.4-A3: Pure decision contract for issuing *new* automatic IP bans.
-- This module NEVER reads/writes Redis and NEVER changes request enforcement.
-- Manual bans are managed separately in the existing blacklist_ips SET.
-- Trusted in-process evidence only. Do not populate input from client headers,
-- user JSON or a single uncorroborated risk score.
-- Lua 5.1 / LuaJIT compatible.

local M = {}
local MAX_TTL_SECONDS = 300

local function denied(reason)
    return {
        approved = false,
        action = "DENY_ISSUANCE",
        reason = reason,
        scope = "ip",
        ttl_seconds = nil,
    }
end

local function valid_uint(value)
    return type(value) == "number" and value == value
        and value >= 0 and value < math.huge and value % 1 == 0
end

local function valid_ip_text(value)
    -- Only a syntax guard, NOT an IP trust determination. The ingress must
    -- supply the already-validated/canonical TCP peer address.
    return type(value) == "string" and #value > 2 and #value <= 45
        and value:match("^[0-9a-fA-F:.]+$") ~= nil
        and (value:find(".", 1, true) ~= nil or value:find(":", 1, true) ~= nil)
end

local function valid_incident_id(id)
    -- Bounded, non-PII incident reference created by a trusted correlator.
    return type(id) == "string" and #id >= 16 and #id <= 64
        and id:match("^[a-f0-9]+$") ~= nil
end

-- The only issuance path reserved for future A3 correlation implementation.
-- A raw WAF match, a rate-limit, a failed-login counter, a JWT error or a
-- risk score is NOT enough to issue an IP ban.
function M.authorize(candidate)
    if type(candidate) ~= "table" then return nil, "invalid_candidate" end
    if candidate.mode ~= "automatic" then
        return denied("not_automatic_issuance")
    end
    if candidate.scope ~= "ip" then
        return denied("wrong_scope")
    end
    if candidate.issuer ~= "security_correlator" then
        return denied("untrusted_issuer")
    end
    if not valid_ip_text(candidate.ip) or candidate.peer_ip_verified ~= true then
        return denied("unverified_ip_identity")
    end
    if not valid_uint(candidate.ttl_seconds) or candidate.ttl_seconds < 1 then
        return nil, "invalid_ttl"
    end

    local ev = candidate.evidence
    if type(ev) ~= "table" then
        return denied("evidence_missing")
    end
    if ev.reason ~= "confirmed_exploit_campaign" then
        return denied("unsupported_reason")
    end
    if not valid_incident_id(ev.incident_id) then
        return denied("invalid_incident_reference")
    end
    if ev.server_verified ~= true or ev.independent_sources_verified ~= true then
        return denied("unverified_evidence")
    end
    -- Conservatively reject unknown/shared-IP cases. The correlator must
    -- justify low collateral impact; an IP's country or score is insufficient.
    if ev.nat_assessment ~= "low_collateral_verified" or ev.shared_ip_observed ~= false then
        return denied("shared_ip_or_unknown_collateral")
    end
    if not valid_uint(ev.confirmed_exploit_events)
        or not valid_uint(ev.distinct_windows)
        or not valid_uint(ev.distinct_attack_classes)
        or not valid_uint(ev.first_seen)
        or not valid_uint(ev.last_seen) then
        return denied("invalid_evidence_counts")
    end
    -- Multiple independently verified confirmed exploits, across time.
    -- All counts refer to server-verified individual requests, not UA strings.
    if ev.confirmed_exploit_events < 8
        or ev.distinct_windows < 3
        or ev.distinct_attack_classes < 2
        or ev.last_seen < ev.first_seen
        or ev.last_seen - ev.first_seen < 120 then
        return denied("insufficient_corroboration")
    end
    return {
        approved = true,
        action = "AUTHORIZE_TEMP_IP_BAN",
        scope = "ip",
        reason = "confirmed_exploit_campaign",
        ttl_seconds = math.min(candidate.ttl_seconds, MAX_TTL_SECONDS),
        incident_id = ev.incident_id,
        -- A separate Redis writer MUST revalidate this decision & bind it to
        -- its own trusted evidence. This is NOT a bearer capability/token.
    }
end

M.MAX_TTL_SECONDS = MAX_TTL_SECONDS
return M
