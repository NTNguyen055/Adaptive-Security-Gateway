local _M = {}
local math_min = math.min
local utils = require "utils"
local geo = require "resty.maxminddb"

-- =============================================================================
-- CONFIG
-- =============================================================================

local ALLOWED_COUNTRIES = {
    ["VN"] = true,
    ["US"] = true,
    ["SG"] = true,
    ["JP"] = true,
}

-- LEVEL 4: GEO multiplier (quan trọng)
local GEO_MULTIPLIER = {
    VN = 1.0,
    US = 1.1,
    SG = 1.05,
    JP = 1.0,

    CN = 1.4,
    RU = 1.5,
    KP = 1.6,

    UNKNOWN = 1.3
}

-- Risk matrix (LEVEL 3)
local GEO_RISK_MATRIX = {
    base_foreign = 25,

    bad_bot_scanner = 10,
    rate_limit_hard = 15,
    empty_ua = 10,

    xff_spoof = 20,
    xff_malformed = 15,

    brute_force_attack = 25,
    jwt_replay = 20
}

-- =============================================================================
-- MAIN
-- =============================================================================
function _M.run(ctx)

    local ip = (ctx.security and ctx.security.client_ip)
        or ngx.var.realip_remote_addr
        or ngx.var.remote_addr

    ctx.security = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    -- Private IP skip geo
    if not ip or utils.is_private_ip(ip) then
        ctx.security.geo_private = true
        table.insert(ctx.security.signals, "geo_private")
        return
    end

    -- Lookup geo
    local res, err = geo.lookup(ip)

    if not res then
        ngx.log(ngx.ERR, "[GEO] lookup failed ip=", ip, " err=", err or "unknown")
        ctx.security.geo_lookup_fail = true
        return
    end

    local country = res.country and res.country.iso_code
    if not country then
        ctx.security.geo_unknown = true
        country = "UNKNOWN"
    end

    ctx.security.geo_country = country

    -- Allowed countries → bypass block
    if ALLOWED_COUNTRIES[country] then
        ctx.security.geo_allowed = true
        return
    end

    -- =========================
    -- BLOCK TRIGGER
    -- =========================
    ctx.security.geo_blocked = true
    ctx.security.block = true

    -- =========================
    -- RISK SCORING (LEVEL 3 + 4 + 5)
    -- =========================

    local risk_add = GEO_RISK_MATRIX.base_foreign

    if ctx.security.bad_bot_scanner then
        risk_add = risk_add + GEO_RISK_MATRIX.bad_bot_scanner
    end

    if ctx.security.rate_limit_hard then
        risk_add = risk_add + GEO_RISK_MATRIX.rate_limit_hard
    end

    if ctx.security.empty_ua then
        risk_add = risk_add + GEO_RISK_MATRIX.empty_ua
    end

    if ctx.security.xff_spoof then
        risk_add = risk_add + GEO_RISK_MATRIX.xff_spoof
    end

    if ctx.security.xff_malformed then
        risk_add = risk_add + GEO_RISK_MATRIX.xff_malformed
    end

    if ctx.security.brute_force_attack then
        risk_add = risk_add + GEO_RISK_MATRIX.brute_force_attack
    end

    if ctx.security.jwt_replay then
        risk_add = risk_add + GEO_RISK_MATRIX.jwt_replay
    end

    -- =========================
    -- LEVEL 4: MULTIPLICATIVE RISK (IMPORTANT FIX)
    -- =========================
    local multiplier = GEO_MULTIPLIER[country] or GEO_MULTIPLIER.UNKNOWN

    -- combo attack amplification
    if ctx.security.bad_bot_scanner and not ALLOWED_COUNTRIES[country] then
        multiplier = multiplier + 0.2
    end

    if ctx.security.rate_limit_hard then
        multiplier = multiplier + 0.1
    end

    if ctx.security.xff_spoof then
        multiplier = multiplier + 0.2
    end

    risk_add = risk_add * multiplier

    -- clamp
    risk_add = math_min(risk_add, 100)

    -- apply
    ctx.security.risk = math_min((ctx.security.risk or 0) + risk_add, 100)

    table.insert(ctx.security.signals, "geo_block:" .. country)

    ngx.log(
        ngx.WARN,
        "[GEO] BLOCK country=",
        country,
        " ip=",
        ip,
        " risk_add=",
        risk_add,
        " multiplier=",
        multiplier
    )
end

return _M