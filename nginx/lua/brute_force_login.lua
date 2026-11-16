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
        risk_penalty = tonumber(
            os.getenv("BRUTE_FORCE_RISK_PENALTY")
        ) or 80,
        cooldown_time = positive_integer(
            os.getenv("BRUTE_FORCE_COOLDOWN"), 3600
        ),
    }
end

-- ============================================================
-- EMERGENCY LOCK: LOCAL SHARED MEMORY
-- ============================================================
local function mark_emergency_lock(ip, ttl, reason)
    if not ip or ip == "" then
        return false, "invalid IP"
    end

    local key = "bf:emergency:" .. ip
    local dictionaries = {}

    if ngx.shared.brute_force_cache then
        table.insert(dictionaries, ngx.shared.brute_force_cache)
    end

    if ngx.shared.ip_cache then
        table.insert(dictionaries, ngx.shared.ip_cache)
    end

    for _, dict in ipairs(dictionaries) do
        if dict then
            local ok, err = dict:set(key, 1, ttl)

            if ok then
                ngx.log(
                    ngx.ALERT,
                    "[BRUTE_FORCE] Emergency lock activated for IP ",
                    ip,
                    ", TTL=",
                    ttl,
                    "s, reason=",
                    tostring(reason)
                )

                return true
            end

            ngx.log(
                ngx.ERR,
                "[BRUTE_FORCE] Emergency dictionary write failed: ",
                tostring(err)
            )
        end
    end

    -- Không thể bảo đảm trạng thái bảo vệ theo IP.
    -- Đánh dấu gateway degraded để pre-login fail closed.
    for _, dict in ipairs(dictionaries) do
        if dict then
            local ok = dict:set("bf:gateway_degraded", 1, ttl)

            if ok then
                ngx.log(
                    ngx.ALERT,
                    "[BRUTE_FORCE] Gateway entered degraded security mode"
                )
                return false, "gateway security degraded"
            end
        end
    end

    ngx.log(
        ngx.CRIT,
        "[BRUTE_FORCE] CRITICAL: Cannot persist emergency security state"
    )

    return false, "emergency state unavailable"
end

function _M.record_failed_attempt_fallback(ctx, reason)
    ctx = ctx or {}

    local cfg = get_config()
    local ip = ctx.client_ip
        or ngx.var.remote_addr
        or ngx.var.realip_remote_addr

    if not ip or ip == "" then
        ngx.log(
            ngx.CRIT,
            "[BRUTE_FORCE] Cannot activate fallback: missing client IP"
        )
        return false
    end

    return mark_emergency_lock(
        ip,
        cfg.cooldown_time,
        reason or "failed attempt could not be recorded"
    )
end

-- ============================================================
-- REDIS ATOMIC SCRIPT: INCR + TTL
-- ============================================================
local INCREMENT_ATTEMPT_SCRIPT = [[
    local count = redis.call("INCR", KEYS[1])

    if count == 1 then
        redis.call("EXPIRE", KEYS[1], ARGV[1])
    end

    if count >= tonumber(ARGV[2]) then
        redis.call("EXPIRE", KEYS[1], ARGV[3])
    end

    return count
]]

-- ============================================================
-- REDIS ATOMIC SCRIPT: UPDATE RISK REPUTATION
-- ============================================================
local UPDATE_REPUTATION_SCRIPT = [[
    local current = tonumber(redis.call("GET", KEYS[1])) or 0
    local amount = tonumber(ARGV[1])
    local low_ttl = tonumber(ARGV[2])
    local high_ttl = tonumber(ARGV[3])

    local updated = math.min(current + amount, 100)

    local ttl = low_ttl
    if updated >= 80 then
        ttl = high_ttl
    end

    redis.call(
        "SET",
        KEYS[1],
        string.format("%.2f", updated),
        "EX",
        ttl
    )

    return tostring(updated)
]]

-- ============================================================
-- REDIS ATOMIC SCRIPT: PERSIST BRUTE FORCE BLOCK
-- ============================================================
local PERSIST_BRUTE_FORCE_BLOCK_SCRIPT = [[
    redis.call("SET", KEYS[1], "1", "EX", ARGV[1])
    redis.call("SET", KEYS[2], "1", "EX", ARGV[1])

    return 1
]]

-- ============================================================
-- HELPER: UPDATE RISK REPUTATION
-- ============================================================
local function add_risk_reputation(ip, amount, red)
    if not ip or not red then
        return nil, "invalid IP or Redis connection"
    end

    amount = tonumber(amount) or 0
    if amount <= 0 then
        return nil, "invalid reputation amount"
    end

    local key = "risk:v1:" .. ip

    local result, err = red:eval(
        UPDATE_REPUTATION_SCRIPT,
        1,
        key,
        amount,
        86400,
        31536000
    )

    if not result then
        ngx.log(
            ngx.ERR,
            "[BRUTE_FORCE] Cannot update reputation for IP ",
            ip,
            ": ",
            tostring(err)
        )
        return nil, err
    end

    local new_score = tonumber(result)

    if not new_score then
        ngx.log(
            ngx.ERR,
            "[BRUTE_FORCE] Invalid reputation result for IP ",
            ip
        )
        return nil, "invalid reputation result"
    end

    local ttl = new_score >= 80 and 31536000 or 86400

    ngx.log(
        ngx.WARN,
        "[BRUTE_FORCE] Risk reputation updated for IP ",
        ip,
        ": score=",
        new_score,
        " TTL=",
        ttl,
        "s"
    )

    return new_score
end

-- ============================================================
-- HELPER: PERSIST BRUTE FORCE BLOCK
-- ============================================================
local function persist_brute_force_block(ip, red, ttl)
    if not ip or not red then
        return false, "invalid IP or Redis connection"
    end

    if not ttl or ttl < 1 or ttl % 1 ~= 0 then
        return false, "invalid block TTL"
    end

    local lockout_key = "brute_force:lockout:" .. ip
    local blacklist_key = "blacklist:" .. ip

    local result, err = red:eval(
        PERSIST_BRUTE_FORCE_BLOCK_SCRIPT,
        2,
        lockout_key,
        blacklist_key,
        ttl
    )

    if result ~= 1 then
        ngx.log(
            ngx.ERR,
            "[BRUTE_FORCE] Failed to persist lockout and blacklist for IP ",
            ip,
            ": ",
            tostring(err)
        )

        return false, err or "invalid block persistence result"
    end

    -- Chỉ cập nhật L1 cache sau khi Redis ghi thành công.
    if ngx.shared.ip_cache then
        local cached, cache_err = ngx.shared.ip_cache:set(
            "bl:" .. ip,
            1,
            ttl
        )

        if not cached then
            ngx.log(
                ngx.WARN,
                "[BRUTE_FORCE] Redis block persisted but L1 cache failed for IP ",
                ip,
                ": ",
                tostring(cache_err)
            )
        end
    end

    ngx.log(
        ngx.WARN,
        "[BRUTE_FORCE] IP ",
        ip,
        " blocked (lockout + blacklist, TTL=",
        ttl,
        "s)"
    )

    return true
end

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
-- HELPER: CHECK IP LOCKOUT
-- ============================================================
local function is_ip_locked(ip, red)
    if not ip or not red then
        return nil, "invalid IP or Redis connection"
    end

    local lock_key = "brute_force:lockout:" .. ip

    local locked, err = red:get(lock_key)

    if not locked then
        return nil, err or "Redis GET failed"
    end

    return locked ~= ngx.null
end

-- ============================================================
-- MAIN: FAILED LOGIN
-- ============================================================
function _M.record_failed_attempt(ctx)
    ctx = ctx or {}

    local cfg = get_config()
    local ip = ctx.client_ip
        or ngx.var.remote_addr
        or ngx.var.realip_remote_addr

    if not ip or ip == "" then
        ngx.log(ngx.ERR, "[BRUTE_FORCE] Cannot determine client IP")
        return false
    end

    -- Chỉ sử dụng một Redis connection cho toàn bộ lần xử lý.
    local red, err = redis_helper.get_redis(0)

    if not red then
        ngx.log(
            ngx.ERR,
            "[BRUTE_FORCE] Redis unavailable; failed attempt was not persisted for IP ",
            ip,
            ": ",
            tostring(err)
        )
        return _M.record_failed_attempt_fallback(
            {client_ip = ip},
            "Redis connection failure"
        )
    end

    -- Kiểm tra lockout trước khi tăng counter.
    local locked, lock_err = is_ip_locked(ip, red)

    if locked == nil then
        ngx.log(
            ngx.ERR,
            "[BRUTE_FORCE] Cannot verify lockout state for IP ",
            ip,
            ": ",
            tostring(lock_err)
        )

        redis_helper.close(red)

        return _M.record_failed_attempt_fallback(
            {client_ip = ip},
            "Redis lockout state read failure"
        )
    end

    if locked then
        ctx.brute_force = ctx.brute_force or {}
        ctx.brute_force.is_locked = true
        ctx.brute_force.action = "lockout"

        ngx.log(
            ngx.WARN,
            "[BRUTE_FORCE] IP ",
            ip,
            " is already locked"
        )

        redis_helper.close(red)
        return true
    end

    -- Tăng counter và quản lý TTL trong cùng một Redis script.
    local fail_key = "brute_force:fail:" .. ip

    local attempt_count, incr_err = red:eval(
        INCREMENT_ATTEMPT_SCRIPT,
        1,
        fail_key,
        cfg.window_time,
        cfg.max_attempts,
        cfg.cooldown_time
    )

    attempt_count = tonumber(attempt_count)

    if not attempt_count then
        ngx.log(
            ngx.ERR,
            "[BRUTE_FORCE] Atomic counter update failed for IP ",
            ip,
            ": ",
            tostring(incr_err)
        )

        redis_helper.close(red)

        return _M.record_failed_attempt_fallback(
            {client_ip = ip},
            "Redis counter write failure"
        )
    end

    ctx.brute_force = ctx.brute_force or {}
    ctx.brute_force.attempt_count = attempt_count
    ctx.brute_force.max_attempts = cfg.max_attempts

    ngx.log(
        ngx.WARN,
        "[BRUTE_FORCE] Failed login for IP ",
        ip,
        " - attempt: ",
        attempt_count,
        "/",
        cfg.max_attempts
    )

    -- History là dữ liệu bổ trợ, lỗi history không làm mất counter.
    track_persistent_attempt(ip, attempt_count, red)

    -- ========================================================
    -- GRADUATED PENALTY
    -- ========================================================
    if attempt_count == 3 then
        ctx.brute_force.action = "warn_level_1"
        ctx.brute_force.challenge = true

        ctx.security = ctx.security or {}
        ctx.security.signals = ctx.security.signals or {}

        table.insert(
            ctx.security.signals,
            "brute_force_warning:3_attempts"
        )

        ngx.log(
            ngx.WARN,
            "[BRUTE_FORCE] 3 failed attempts for IP ",
            ip
        )

    elseif attempt_count == 4 then
        ctx.brute_force.action = "warn_level_2"
        ctx.brute_force.challenge = true

        ctx.security = ctx.security or {}
        ctx.security.risk = (ctx.security.risk or 0) + 10
        ctx.security.signals = ctx.security.signals or {}

        table.insert(
            ctx.security.signals,
            "brute_force_warning:4_attempts"
        )

        ngx.log(
            ngx.WARN,
            "[BRUTE_FORCE] 4 failed attempts for IP ",
            ip,
            " - +10 risk points"
        )

    elseif attempt_count >= cfg.max_attempts then
        ctx.brute_force.action = "block"
        ctx.brute_force.exceed = true
        ctx.brute_force.block_now = true

        ctx.security = ctx.security or {}
        ctx.security.signals = ctx.security.signals or {}
        ctx.security.risk = (ctx.security.risk or 0) + cfg.risk_penalty
        ctx.security.block = true

        table.insert(
            ctx.security.signals,
            "brute_force_attack"
        )

        table.insert(
            ctx.security.signals,
            "brute_force_attempt:" .. tostring(attempt_count)
        )

        local block_ok, block_err = persist_brute_force_block(
            ip,
            red,
            cfg.cooldown_time
        )

        if not block_ok then
            ngx.log(
                ngx.ERR,
                "[BRUTE_FORCE] CRITICAL: Failed to persist brute-force block for IP ",
                ip,
                ": ",
                tostring(block_err)
            )
        end

        local final_risk = add_risk_reputation(
            ip,
            cfg.risk_penalty,
            red
        )

        if block_ok then
            ngx.log(
                ngx.ALERT,
                "[BRUTE_FORCE] IP ",
                ip,
                " exceeded max attempts. Lockout and blacklist persisted=true, risk=",
                tostring(final_risk)
            )

            local alert_ok, alert_err = pcall(
                telegram_alert.send,
                {
                    ip = ip,
                    attack_type = "Brute Force Login",
                    score = final_risk or cfg.risk_penalty,
                    details = string.format(
                        "IP vượt quá số lần đăng nhập thất bại tối đa (%d/%d). Lockout và automatic blacklist đã được lưu, TTL=%d giây.",
                        attempt_count,
                        cfg.max_attempts,
                        cfg.cooldown_time
                    )
                }
            )

            if not alert_ok then
                ngx.log(
                    ngx.ERR,
                    "[BRUTE_FORCE] Telegram alert failed: ",
                    tostring(alert_err)
                )
            end
        end
    else
        ctx.brute_force.action = "pass"
    end

    redis_helper.close(red)
    return false
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
-- CHECK: PRE-LOGIN
-- ============================================================
function _M.check_prelogin(ctx)
    ctx = ctx or {}

    local cfg = get_config()
    local ip = ctx.client_ip
        or ngx.var.remote_addr
        or ngx.var.realip_remote_addr

    if not ip or ip == "" then
        ngx.log(
            ngx.ERR,
            "[BRUTE_FORCE] Cannot determine IP during pre-login"
        )
        return nil, "cannot determine client IP"
    end

    -- 0. Emergency state must be checked before Redis.
    local emergency_key = "bf:emergency:" .. ip

    local emergency_dicts = {}

    if ngx.shared.brute_force_cache then
        table.insert(emergency_dicts, ngx.shared.brute_force_cache)
    end

    if ngx.shared.ip_cache then
        table.insert(emergency_dicts, ngx.shared.ip_cache)
    end

    for _, dict in ipairs(emergency_dicts) do
        if dict then
            local degraded = dict:get("bf:gateway_degraded")

            if degraded then
                ngx.log(
                    ngx.ERR,
                    "[BRUTE_FORCE] Gateway security degraded; rejecting login"
                )

                return nil, "gateway security degraded"
            end

            local emergency_locked = dict:get(emergency_key)

            if emergency_locked then
                ctx.brute_force = ctx.brute_force or {}
                ctx.brute_force.action = "emergency_lock"
                ctx.brute_force.is_locked = true

                ngx.log(
                    ngx.WARN,
                    "[BRUTE_FORCE] Emergency lock active for IP ",
                    ip
                )

                return true
            end
        end
    end

    local red, err = redis_helper.get_redis(0)

    if not red then
        ngx.log(
            ngx.ERR,
            "[BRUTE_FORCE] Redis unavailable during pre-login for IP ",
            ip,
            ": ",
            tostring(err)
        )
        return nil, err or "Redis unavailable"
    end

    -- 1. Kiểm tra lockout đã được lưu.
    local locked, lock_err = is_ip_locked(ip, red)

    if locked == nil then
        redis_helper.close(red)

        ngx.log(
            ngx.ERR,
            "[BRUTE_FORCE] Cannot verify pre-login lockout for IP ",
            ip,
            ": ",
            tostring(lock_err)
        )
        return nil, lock_err or "Cannot verify lockout"
    end

    if locked then
        redis_helper.close(red)

        ctx.brute_force = ctx.brute_force or {}
        ctx.brute_force.action = "block_prelogin"
        ctx.brute_force.is_locked = true

        ngx.log(
            ngx.WARN,
            "[BRUTE_FORCE] IP ",
            ip,
            " attempted login during lockout"
        )

        return true
    end

    -- 2. Kiểm tra counter để phát hiện trường hợp
    -- counter đã vượt ngưỡng nhưng lockout chưa được lưu.
    local fail_key = "brute_force:fail:" .. ip
    local attempts, attempts_err = red:get(fail_key)

    if not attempts then
        redis_helper.close(red)

        ngx.log(
            ngx.ERR,
            "[BRUTE_FORCE] Cannot read failure counter for IP ",
            ip,
            ": ",
            tostring(attempts_err)
        )

        return nil, attempts_err or "Cannot read failure counter"
    end

    local attempt_count = 0

    if attempts ~= ngx.null then
        attempt_count = tonumber(attempts)

        if not attempt_count then
            redis_helper.close(red)

            ngx.log(
                ngx.ERR,
                "[BRUTE_FORCE] Invalid failure counter for IP ",
                ip
            )

            return nil, "Invalid failure counter"
        end
    end

    redis_helper.close(red)

    if attempt_count >= cfg.max_attempts then
        ctx.brute_force = ctx.brute_force or {}
        ctx.brute_force.action = "block_prelogin"
        ctx.brute_force.is_locked = true
        ctx.brute_force.attempt_count = attempt_count

        ngx.log(
            ngx.WARN,
            "[BRUTE_FORCE] IP ",
            ip,
            " reached failure threshold during pre-login: ",
            attempt_count
        )

        return true
    end

    return false
end

-- ============================================================
-- EXPORT
-- ============================================================
return _M
