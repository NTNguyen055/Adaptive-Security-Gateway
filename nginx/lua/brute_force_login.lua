-- =============================================================================
-- File: nginx/lua/brute_force_login.lua
-- Chức năng: Chống Brute-force Login thông minh
-- =============================================================================

local _M = {}
local redis_helper = require "redis_helper"
local telegram_alert = require "telegram_alert"

local ngx = ngx
local tonumber = tonumber
local tostring = tostring
local string = string
local math = math
local os = os

-- ============================================================
-- CONFIG
-- ============================================================
local function positive_integer(value, fallback)
    local parsed = tonumber(value)

    if not parsed or parsed < 1 or parsed % 1 ~= 0 then
        return fallback
    end

    return parsed
end

local function get_config()
    return {
        max_attempts = positive_integer(
            os.getenv("BRUTE_FORCE_MAX_ATTEMPTS"), 5
        ),
        window_time = positive_integer(
            os.getenv("BRUTE_FORCE_WINDOW"), 300
        ),
    }
end

-- ============================================================
-- Bounded accounting-health latch, NOT an IP lock.
-- ============================================================
local ACCOUNTING_DEGRADED_TTL = 10

local function mark_accounting_degraded(reason)
    local shared = ngx.shared or {}
    local dictionaries = {}

    if shared.brute_force_cache then
        dictionaries[#dictionaries + 1] = shared.brute_force_cache
    end

    if shared.ip_cache then
        dictionaries[#dictionaries + 1] = shared.ip_cache
    end

    for _, dict in ipairs(dictionaries) do
        local ok, err = dict:set(
            "bf:gateway_degraded",
            1,
            ACCOUNTING_DEGRADED_TTL
        )

        if ok then
            ngx.log(
                ngx.ERR,
                "[BRUTE_FORCE] Accounting degraded for up to ",
                ACCOUNTING_DEGRADED_TTL,
                "s; reason=",
                tostring(reason)
            )

            return false, "accounting degraded"
        end

        ngx.log(
            ngx.ERR,
            "[BRUTE_FORCE] Degraded latch write failed: ",
            tostring(err)
        )
    end

    ngx.log(
        ngx.CRIT,
        "[BRUTE_FORCE] Cannot publish accounting degraded state"
    )

    return false, "accounting degraded without shared latch"
end

function _M.record_failed_attempt_fallback(ctx, reason)
    -- Infrastructure failure is not evidence that an IP is malicious.
    -- No bf:emergency:<ip>, blacklist:<ip> or IP lockout writes.
    return mark_accounting_degraded(
        reason or "failed attempt was not recorded"
    )
end

-- ============================================================
-- Atomic failed-login telemetry.
-- No IP lockout, blacklist or reputation writes.
-- ============================================================
local INCREMENT_ATTEMPT_SCRIPT = [[
    local count = redis.call("INCR", KEYS[1])

    if count == 1 or redis.call("TTL", KEYS[1]) < 0 then
        redis.call("EXPIRE", KEYS[1], ARGV[1])
    end

    return count
]]

-- ============================================================
-- HELPER: TRACK PERSISTENT ATTEMPTS
-- ============================================================
local function track_persistent_attempt(ip, attempt_count, red)
    if not ip or not red then
        return false
    end

    local history_key = "brute_force:history:" .. ip

    local history, err = red:get(history_key)

    if not history then
        ngx.log(
            ngx.WARN,
            "[BRUTE_FORCE] Cannot read attempt history for IP ",
            ip,
            ": ",
            tostring(err)
        )
        return false
    end

    if history == ngx.null then
        history = ""
    end

    local new_entry = tostring(ngx.now()) .. ":" .. tostring(attempt_count)

    if history == "" then
        history = new_entry
    else
        history = new_entry .. "," .. history

        local entries = {}
        for entry in history:gmatch("[^,]+") do
            entries[#entries + 1] = entry

            if #entries >= 10 then
                break
            end
        end

        history = table.concat(entries, ",")
    end

    local ok, set_err = red:set(
        history_key,
        history,
        "EX",
        86400
    )

    if not ok then
        ngx.log(
            ngx.WARN,
            "[BRUTE_FORCE] Cannot save attempt history for IP ",
            ip,
            ": ",
            tostring(set_err)
        )
        return false
    end

    ngx.log(
        ngx.DEBUG,
        "[BRUTE_FORCE] History tracked for IP ",
        ip,
        " - entry: ",
        new_entry
    )

    return true
end

-- ============================================================
-- Observe failed login attempts without IP punishment.
-- ============================================================
function _M.record_failed_attempt(ctx)
    ctx = ctx or {}

    local cfg = get_config()

    local ip = ctx.client_ip
        or ngx.var.remote_addr
        or ngx.var.realip_remote_addr

    if not ip or ip == "" then
        ngx.log(
            ngx.ERR,
            "[BRUTE_FORCE] Missing client IP for telemetry"
        )

        return _M.record_failed_attempt_fallback(
            ctx,
            "missing client IP"
        )
    end

    local red, err = redis_helper.get_redis(0)

    if not red then
        ngx.log(
            ngx.ERR,
            "[BRUTE_FORCE] Accounting Redis unavailable: ",
            tostring(err)
        )

        return _M.record_failed_attempt_fallback(
            ctx,
            "Redis connection failure"
        )
    end

    local count_raw, counter_err = red:eval(
        INCREMENT_ATTEMPT_SCRIPT,
        1,
        "brute_force:fail:" .. ip,
        cfg.window_time
    )

    local count = tonumber(count_raw)

    if not count or count < 1 or count % 1 ~= 0 then
        ngx.log(
            ngx.ERR,
            "[BRUTE_FORCE] Invalid counter response: ",
            tostring(counter_err)
        )

        redis_helper.close(red)

        return _M.record_failed_attempt_fallback(
            ctx,
            "counter EVAL failure"
        )
    end

    ctx.brute_force = ctx.brute_force or {}
    ctx.brute_force.attempt_count = count
    ctx.brute_force.max_attempts = cfg.max_attempts

    ctx.brute_force.action =
        count >= cfg.max_attempts
        and "observe_threshold"
        or "observe"

    -- Forensic history only.
    -- Never interpret history as authorization for IP punishment.
    track_persistent_attempt(ip, count, red)

    redis_helper.close(red)

    -- Send only once when this fixed-window counter first reaches
    -- the observation threshold.
    if count == cfg.max_attempts then
        ngx.log(
            ngx.WARN,
            "[BRUTE_FORCE] Shared-IP failure threshold observed ip=",
            ip,
            " count=",
            count,
            "; no IP ban issued"
        )

        local ok, result = pcall(
            telegram_alert.send,
            {
                ip = ip,
                attack_type =
                    "Repeated Login Failures (observe-only)",
                details =
                    "Source failure threshold observed; " ..
                    "no IP lockout or blacklist issued"
            }
        )

        if not ok or result == false then
            ngx.log(
                ngx.ERR,
                "[BRUTE_FORCE] Observation alert failed: ",
                tostring(result)
            )
        end
    end

    return true
end

-- ============================================================
-- MAIN: SUCCESSFUL LOGIN
-- Không reset failed counter.
-- ============================================================
function _M.record_successful_login(ctx)
    ctx = ctx or {}

    local ip = ctx.client_ip
        or ngx.var.remote_addr
        or ngx.var.realip_remote_addr

    if not ip or ip == "" then
        ngx.log(ngx.WARN, "[BRUTE_FORCE] Cannot determine IP for successful login")
        return false
    end

    local red, err = redis_helper.get_redis(0)

    if not red then
        ngx.log(
            ngx.WARN,
            "[BRUTE_FORCE] Redis unavailable when recording successful login: ",
            tostring(err)
        )
        return false
    end

    local success_key = "brute_force:success:" .. ip

    local ok, set_err = red:set(
        success_key,
        tostring(ngx.now()),
        "EX",
        get_config().window_time
    )

    redis_helper.close(red)

    if not ok then
        ngx.log(
            ngx.ERR,
            "[BRUTE_FORCE] Failed to record successful login for IP ",
            ip,
            ": ",
            tostring(set_err)
        )
        return false
    end

    ngx.log(
        ngx.INFO,
        "[BRUTE_FORCE] Successful login recorded for IP ",
        ip,
        " (failed counter preserved)"
    )

    return true
end

-- ============================================================
-- HELPER: CLEAR COUNTER (DEPRECATED)
-- ============================================================
function _M.clear_failed_attempts(ctx)
    ngx.log(
        ngx.INFO,
        "[BRUTE_FORCE] Failed counter is managed by Redis TTL; no manual reset"
    )
end

-- ============================================================
-- Pre-login accounting health check.
-- Failure counts are telemetry, never IP-lockout authority.
-- ============================================================
function _M.check_prelogin(ctx)
    ctx = ctx or {}

    local ip = ctx.client_ip
        or ngx.var.remote_addr
        or ngx.var.realip_remote_addr

    if not ip or ip == "" then
        return nil, "cannot determine client IP"
    end

    local shared = ngx.shared or {}
    local dictionaries = {}

    if shared.brute_force_cache then
        dictionaries[#dictionaries + 1] = shared.brute_force_cache
    end

    if shared.ip_cache then
        dictionaries[#dictionaries + 1] = shared.ip_cache
    end

    for _, dict in ipairs(dictionaries) do
        if dict:get("bf:gateway_degraded") then
            return nil, "gateway accounting degraded"
        end
    end

    local red, err = redis_helper.get_redis(0)

    if not red then
        ngx.log(
            ngx.ERR,
            "[BRUTE_FORCE] Redis unavailable at pre-login: ",
            tostring(err)
        )

        return nil, "accounting Redis unavailable"
    end

    local raw, read_err = red:get(
        "brute_force:fail:" .. ip
    )

    redis_helper.close(red)

    if raw == nil then
        ngx.log(
            ngx.ERR,
            "[BRUTE_FORCE] Failure-counter read unavailable: ",
            tostring(read_err)
        )

        return nil, "accounting counter unavailable"
    end

    if raw ~= ngx.null then
        local count = tonumber(raw)

        if not count
            or count < 0
            or count % 1 ~= 0 then

            return nil, "invalid failure counter"
        end

        ctx.brute_force = ctx.brute_force or {}
        ctx.brute_force.attempt_count = count
        ctx.brute_force.threshold_observed =
            count >= get_config().max_attempts
    end

    return false
end

-- ============================================================
-- EXPORT
-- ============================================================
return _M
