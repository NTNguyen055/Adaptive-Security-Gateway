local _M = {}

local ngx        = ngx
local tonumber   = tonumber
local math_min   = math.min
local redis_helper = require "redis_helper" -- FIX 1: Tái sử dụng redis_helper.lua
local telegram_alert = require "telegram_alert"

-- ============================================================
-- CONFIG
-- ============================================================
local function get_config()
    return {
        -- Ngưỡng hành động của Risk Engine:
        -- Đạt 50 điểm sẽ bị Limit (giới hạn / Captcha), đạt 80 điểm sẽ bị Block (chặn hoàn toàn).
        block_threshold = tonumber(os.getenv("RISK_BLOCK_THRESHOLD")) or 80,
        limit_threshold = tonumber(os.getenv("RISK_LIMIT_THRESHOLD")) or 50,
        -- Time-based reputation decay.  Decay is applied to stored reputation
        -- when a *subsequent confirmed attack* is evaluated, not on clean traffic.
        -- Opt out with RISK_DECAY_ENABLED=false if the deployment requires it.
        decay_enabled = (os.getenv("RISK_DECAY_ENABLED") or "true"):lower() == "true",
        -- Fraction removed per 5-minute period (clamped to [0, 1]).
        decay_factor = tonumber(os.getenv("RISK_DECAY_FACTOR")) or 0.1,
    }
end

local MAX_RISK = 100

-- Time-bounded IP reputation and automatic blocks (local baseline).
-- Automatic blocks must not populate the persistent manual-ban set.
local REPUTATION_TTL_NORMAL = 3600       -- 1 hour
local REPUTATION_TTL_ELEVATED = 7200     -- 2 hours
local AUTOMATIC_BLOCK_TTL = 900         -- 15 minutes
local REPUTATION_DECAY_PERIOD = 300       -- 5 minutes

-- Compare-and-swap: check the exact snapshot read by this request before
-- committing score, timestamp, and auto-ban in one EVAL.  A conflicting
-- concurrent request returns 0; the caller MUST reload and recompute.
-- This prevents silent lost updates while retaining the existing scoring code.
-- Redis scripts are atomic in execution/visibility, but not rollback-on-error.
local WRITE_REPUTATION_SCRIPT = [[
local score_key = KEYS[1]
local seen_key = KEYS[2]
local ban_key = KEYS[3]
local history_key = KEYS[4]
local score = tonumber(ARGV[1])
local rep_ttl = tonumber(ARGV[2])
local seen_at = tonumber(ARGV[3])
local write_seen = tonumber(ARGV[4])
local write_ban = tonumber(ARGV[5])
local ban_ttl = tonumber(ARGV[6])
local expected_score = ARGV[7]
local expected_seen = ARGV[8]
local expected_history = ARGV[9]
local MISSING = '__ASG_MISSING__'
if not score or score ~= score or score < 0 or score > 100
    or not rep_ttl or rep_ttl < 1 or rep_ttl > 7200
    or not ban_ttl or ban_ttl < 1 or ban_ttl > 900
    or (write_seen == 1 and not seen_at)
    or (write_seen ~= 0 and write_seen ~= 1)
    or (write_ban ~= 0 and write_ban ~= 1)
    or not expected_score or not expected_seen or not expected_history then
    return redis.error_reply('invalid reputation script args')
end
-- Do not accept stale updates, including stale brute-force history.
if (redis.call('GET', score_key) or MISSING) ~= expected_score then return 0 end
if write_seen == 1 and
    (redis.call('GET', seen_key) or MISSING) ~= expected_seen then return 0 end
if (redis.call('GET', history_key) or MISSING) ~= expected_history then return 0 end
redis.call('SET', score_key, ARGV[1], 'EX', rep_ttl)
if write_seen == 1 then
    redis.call('SET', seen_key, ARGV[3], 'EX', rep_ttl)
end
if write_ban == 1 then
    redis.call('SET', ban_key, '1', 'EX', ban_ttl)
end
return 1
]]
local MAX_REPUTATION_RETRIES = 24
local MISSING_REDIS_VALUE = '__ASG_MISSING__'

local function bounded_decay_factor(value)
    if value ~= value then return 0.1 end -- NaN protection
    return math.max(0, math.min(1, value))
end

local function current_time()
    -- ngx.now provides wall-clock seconds in OpenResty.  A backwards-clock
    -- guard below prevents accidental forgiveness on clock adjustments.
    -- os.time keeps standalone mock executions compatible.
    return ngx.now and ngx.now() or os.time()
end

-- Redis outage/error is an infrastructure event, not evidence of abuse.
-- Preserve the decision already made by security modules and fall back to
-- this request's score; do not read/write any historical IP reputation.
local function decide_without_reputation(ctx, base_risk, cfg, error_flag)
    ctx.security[error_flag] = true
    ctx.security.risk_final = base_risk
    if base_risk >= cfg.block_threshold then
        ctx.security.risk_action = "block"
        ctx.security.block = true
    elseif ctx.security.block then
        ctx.security.risk_action = "block"
    elseif base_risk >= cfg.limit_threshold then
        ctx.security.risk_action = "limit"
    else
        ctx.security.risk_action = "pass"
    end
    ngx.var.log_risk_score = string.format("%.1f", base_risk)
    ngx.var.log_security_block = ctx.security.risk_action
end

local function discard_connection(red)
    if red and type(red.close) == "function" then
        pcall(function() red:close() end)
    end
end

-- ============================================================
-- SIGNAL CORRELATION
-- ============================================================
-- Bảng quy đổi tín hiệu (Signals) thành Điểm rủi ro (Risk Points).
-- Mỗi khi các module trước (WAF, Bot, Geo, Brute-force) phát hiện bất thường,
-- chúng không chặn ngay mà gắn "signal" vào Request. Risk Engine sẽ tổng hợp ở đây.
local SIGNAL_BONUS = {

    -- XFF
    xff_private_client = 5,
    xff_private_chain  = 25,
    xff_chain_abuse    = 15,
    xff_spoof          = 25,
    xff_malformed      = 10,

    -- Bot
    bad_bot_scanner    = 10,
    bad_bot_headless   = 10,
    dev_tool           = 5,
    empty_ua           = 5,
    ua_unknown         = 5,

    -- WAF
    waf_sqli           = 25,
    waf_xss            = 20,

    -- JWT
    jwt_replay         = 15,
    jwt_alg_attack     = 20,

    -- Rate limit
    rate_limit_hard    = 15,

    -- Geo
    geo_block          = 5,

    -- Brute force
    brute_force_attack = 30,
}

-- ============================================================
-- MAIN
-- ============================================================
function _M.run(ctx)
    local cfg = get_config()

    local ip = (ctx.security and ctx.security.client_ip)
               or ngx.var.realip_remote_addr
               or ngx.var.remote_addr

    ctx.security         = ctx.security or {}
    local base_risk      = ctx.security.risk or 0
    local signals        = ctx.security.signals or {}

    -- ── SIGNAL CORRELATION (Cộng dồn điểm rủi ro ẩn) ──────────
    local bonus = 0
    local signal_set = {}
    for _, s in ipairs(signals) do
        -- Lấy prefix của signal (ví dụ từ bad_bot_scanner:sqlmap thành bad_bot_scanner)
        local base_signal = s:match("^([^:]+)") or s
        signal_set[base_signal] = true
    end

    -- Duyệt qua danh sách signal của Request hiện tại, tra bảng SIGNAL_BONUS để cộng điểm.
    for signal, points in pairs(SIGNAL_BONUS) do
        if signal_set[signal] then
            bonus = bonus + points
        end
    end

    -- Mở rộng các combo nguy hiểm (Combination Bonus)
    -- CORE: Tính năng "Combo Amplification" (Khuếch đại theo chuỗi).
    -- Nếu Attacker phối hợp nhiều phương thức (Vd: Dùng Bot + Scan SQLi), điểm rủi ro sẽ
    -- được cộng thêm (bonus) cực mạnh để ép IP chạm ngưỡng Block (80) ngay lập tức.
    if signal_set["waf_sqli"] and signal_set["bad_bot_scanner"] then bonus = bonus + 15 end
    if signal_set["rate_limit_hard"] and signal_set["geo_block"] then bonus = bonus + 10 end
    if signal_set["jwt_invalid"] and signal_set["rate_limit_hard"] then bonus = bonus + 10 end

    -- Combo mới
    if signal_set["waf_xss"] and signal_set["jwt_missing"] then bonus = bonus + 15 end          -- Tấn công XSS khi chưa đăng nhập
    if signal_set["bad_bot_headless"] and signal_set["waf_sqli"] then bonus = bonus + 20 end    -- Dùng tool tự động để cào Database
    if signal_set["xff_private_client"] and signal_set["jwt_invalid"] then bonus = bonus + 15 end -- Giả mạo IP LAN để phá mật khẩu

    base_risk = math_min(base_risk + bonus, MAX_RISK)

    -- Không ghi hình phạt IP dài hạn chỉ vì request thiếu JWT.
    -- Vẫn cho phép xử lý bình thường nếu có tín hiệu tấn công
    -- độc lập với việc thiếu token.
    local independent_abuse =
        ctx.security.waf_sqli
        or ctx.security.waf_xss
        or ctx.security.rate_limit_hard
        or ctx.security.redis_rate_exceeded
        or ctx.security.bad_bot_scanner
        or ctx.security.xff_spoof
        or ctx.security.xff_chain_abuse
        or ctx.security.brute_force_attack

    if ctx.security.jwt_missing and not independent_abuse then
        ctx.security.block = true
        ctx.security.risk_action = "block"
        ctx.security.risk_final = base_risk

        ngx.var.log_risk_score =
            string.format("%.1f", base_risk)

        ngx.var.log_security_block = "block"

        return
    end

    -- ============================================================
    -- RATE-ONLY MITIGATION GUARD
    -- ============================================================
    -- Vượt rate limit không tự động trở thành hình phạt IP dài hạn.
    -- Chặn request hiện tại nhưng không cập nhật Redis reputation.

    local has_rate_violation =
        ctx.security.rate_limit_hard
        or ctx.security.rate_limit_burst
        or ctx.security.redis_rate_exceeded

    local has_attack_evidence =
        ctx.security.waf_sqli
        or ctx.security.waf_xss
        or ctx.security.bad_bot_scanner
        or ctx.security.bad_bot_headless
        or ctx.security.brute_force_attack
        or ctx.security.xff_spoof
        or ctx.security.xff_chain_abuse
        or ctx.security.xff_malformed
        or ctx.security.xff_private_chain
        or ctx.security.jwt_replay
        or ctx.security.jwt_alg_attack

    if has_rate_violation and not has_attack_evidence then
        ctx.security.block = true

        -- Đánh dấu request chỉ bị giới hạn tốc độ.
        ctx.security.rate_only_limited = true
        ctx.security.risk_action = "limit"
        ctx.security.risk_final = base_risk

        ngx.var.log_risk_score =
            string.format("%.1f", base_risk)

        ngx.var.log_security_block = "limit"

        ngx.log(
            ngx.INFO,
            "[RISK] Rate-only mitigation; no reputation update ip=",
            ip
        )

        return
    end

    -- ============================================================
    -- CONTEXT-ONLY FALSE POSITIVE GUARD
    -- ============================================================
    -- Các tín hiệu ngữ cảnh không đủ để kết luận IP tấn công.
    -- Không tích lũy reputation hoặc blacklist nếu không có
    -- bằng chứng tấn công độc lập.

    local reputation_worthy =
        independent_abuse
        or ctx.security.bad_bot_headless
        or ctx.security.jwt_replay
        or ctx.security.jwt_alg_attack
        or ctx.security.xff_malformed
        or ctx.security.xff_private_chain

    if not reputation_worthy then
        -- Giữ điểm quan sát phục vụ audit.
        ctx.security.risk_final = base_risk

        -- Không ghi Redis reputation cho request chỉ có
        -- tín hiệu ngữ cảnh.
        -- Giữ nguyên quyết định block của module trước nếu có.
        if not ctx.security.risk_action then
            ctx.security.risk_action =
                ctx.security.block and "block" or "pass"
        end

        ngx.var.log_risk_score =
            string.format("%.1f", base_risk)

        ngx.var.log_security_block =
            ctx.security.risk_action

        ngx.log(
            ngx.INFO,
            "[RISK] Context-only request; skip reputation update ip=",
            ip,
            " signals=[",
            table.concat(signals, ","),
            "]"
        )

        return
    end

    -- ── REDIS REPUTATION ──────────────────────────────────────
    -- Kết nối an toàn qua Helper (Tự động Select DB 0)
    local red, err = redis_helper.get_redis(0)

    if not red then
        ngx.log(ngx.WARN, "[RISK] Redis unavailable: ", tostring(err))
        decide_without_reputation(ctx, base_risk, cfg, "redis_risk_fail")
        return
    end

    -- Optimistic read/compare/update loop. Contended writes must not silently
    -- overwrite a concurrent request. Bound retries to protect gateway latency.
    local key = "risk:v1:" .. ip
    local final_risk, reputation, now
    local committed_update = false
    for attempt = 1, MAX_REPUTATION_RETRIES do
        -- Reads must distinguish Redis nil/error from a legitimate ngx.null miss.
        local reputation_raw, rep_err = red:get(key)
        if reputation_raw == nil then
            discard_connection(red)
            ngx.log(ngx.ERR, "[RISK] Reputation read failed: ", tostring(rep_err))
            decide_without_reputation(ctx, base_risk, cfg, "redis_risk_error")
            return
        end
        reputation = nil
        if reputation_raw == ngx.null then
            reputation = 0
        else
            reputation = tonumber(reputation_raw)
        end
        if not reputation or reputation ~= reputation or reputation < 0 or reputation > MAX_RISK then
            discard_connection(red)
            ngx.log(ngx.ERR, "[RISK] Malformed reputation value")
            decide_without_reputation(ctx, base_risk, cfg, "redis_risk_error")
            return
        end

        -- Time-based decay uses the timestamp of the last confirmed abuse, not
        -- the number of clean requests. Clean/context-only requests never write
        -- reputation, so ordinary NAT/CGNAT users cannot refresh punishment.
        local timestamp_key = "risk:v1:last_seen:" .. ip
        now = nil
        local last_seen_raw = ngx.null
        if cfg.decay_enabled then
            now = current_time()
            if reputation > 0 then
                local last_seen_err
                last_seen_raw, last_seen_err = red:get(timestamp_key)
                if last_seen_raw == nil then
                    discard_connection(red)
                    ngx.log(ngx.ERR, "[RISK] Timestamp read failed: ", tostring(last_seen_err))
                    decide_without_reputation(ctx, base_risk, cfg, "redis_risk_error")
                    return
                end
                local last_seen = (last_seen_raw ~= ngx.null)
                    and tonumber(last_seen_raw) or nil
                if last_seen and now > last_seen then
                    local periods = math.floor((now - last_seen) / REPUTATION_DECAY_PERIOD)
                    if periods > 0 then
                        local factor = bounded_decay_factor(cfg.decay_factor)
                        reputation = reputation * math.pow(1 - factor, periods)
                        if reputation < 1 then reputation = 0 end
                        ngx.log(ngx.INFO, "[RISK] Time decay ip=", ip,
                            " periods=", periods,
                            " reputation=", string.format("%.2f", reputation))
                    end
                end
                -- Legacy scores without timestamps are retained until expiry or
                -- the next confirmed abuse establishes their timestamp.
            end
        end

        final_risk = math_min(reputation + base_risk, MAX_RISK)

        -- If reputation is already above block threshold, keep that score for the current request.
        if reputation >= cfg.block_threshold then
            final_risk = reputation
            ngx.log(ngx.WARN, "[RISK] High reputation score detected for IP ", ip, " - reputation=", reputation)
        end

        -- =========================================================================
        -- BRUTE-FORCE REPUTATION TRACKING
        -- Kiểm tra lịch sử brute-force để accumulate risk across windows
        -- =========================================================================
        local bf_history_key = "brute_force:history:" .. ip
        local bf_history, bf_err = red:get(bf_history_key)
        if bf_history == nil then
            discard_connection(red)
            ngx.log(ngx.ERR, "[RISK] Brute-force history read failed: ", tostring(bf_err))
            decide_without_reputation(ctx, base_risk, cfg, "redis_risk_error")
            return
        end

        -- Liên kết dữ liệu chéo module: Đọc lịch sử từ module Brute-force.
        -- Nếu IP này có "tiền án" (high_risk_count > 0) thì đè thêm điểm phạt nặng hơn vào Risk tổng.
        if bf_history and bf_history ~= ngx.null then
            -- Parse history và count high-risk attempts
            local high_risk_count = 0
            for entry in bf_history:gmatch("[^,]+") do
                local _, attempt = entry:match("^([^:]+):(%d+)$")
                if attempt and tonumber(attempt) >= 5 then
                    high_risk_count = high_risk_count + 1
                end
            end

            -- Nếu có lịch sử brute-force >= 5 lần, tăng penalty thêm
            if high_risk_count > 0 then
                local persistent_penalty = high_risk_count * 15
                final_risk = math_min(final_risk + persistent_penalty, MAX_RISK)
                ngx.log(ngx.WARN, "[RISK] Brute-force history detected for IP ", ip,
                        " - high_risk_count=", high_risk_count,
                        " - additional_penalty=", persistent_penalty)
            end
        end

        -- Momentum: Phạt nặng hơn nếu request liên tiếp chứa dấu hiệu xấu
        -- Tăng ngưỡng lên 50 để tránh phạt oan người dùng chỉ mở F12 (Dev_tool)
        -- Nếu reputation đã đạt ngưỡng block, không cộng thêm momentum
        if base_risk > 50 and reputation < cfg.block_threshold then
            final_risk = math_min(final_risk + 10, MAX_RISK)
        end

        -- =========================================================================
        -- TỐI ƯU HÓA REDIS WRITE I/O
        -- Chỉ thực hiện ghi xuống Redis nếu:
        -- 1. IP này vừa gây ra rủi ro (final_risk > 0.01)
        -- 2. Hoặc confirmed abuse references a still-active reputation value.
        -- Clean or context-only traffic returns before this Redis write path.
        -- =========================================================================
        if final_risk >= 0.01 or reputation >= 0.01 then

            -- Bounded reputation lifetime: 1 hour normal / 2 hours elevated.
            -- Both request decisions and IP reputation remain separate from a manual ban.
            local rep_ttl = REPUTATION_TTL_NORMAL
            if final_risk >= cfg.limit_threshold then
                rep_ttl = REPUTATION_TTL_ELEVATED
            end
            local ban_now = final_risk >= cfg.block_threshold
            local committed, write_err = red:eval(
                WRITE_REPUTATION_SCRIPT, 4,
                key, timestamp_key, "blacklist:" .. ip, bf_history_key,
                string.format("%.2f", final_risk), rep_ttl,
                tostring(now or 0), cfg.decay_enabled and 1 or 0,
                ban_now and 1 or 0, AUTOMATIC_BLOCK_TTL,
                reputation_raw == ngx.null and MISSING_REDIS_VALUE or reputation_raw,
                last_seen_raw == ngx.null and MISSING_REDIS_VALUE or last_seen_raw,
                bf_history == ngx.null and MISSING_REDIS_VALUE or bf_history
            )
            if committed == 1 then
                committed_update = true
                if ban_now then
                    ngx.log(ngx.WARN, "[RISK] Temporary auto-block ip=", ip,
                        " final_risk=", string.format("%.1f", final_risk),
                        " ttl=", AUTOMATIC_BLOCK_TTL, "s")
                end
            elseif committed == 0 then
                -- Another request changed this snapshot. Re-read and recompute.
                ngx.log(ngx.INFO, "[RISK] Reputation CAS contention ip=", ip,
                    " attempt=", attempt)
            else
                discard_connection(red)
                ngx.log(ngx.ERR, "[RISK] Atomic reputation EVAL failed: ", tostring(write_err))
                decide_without_reputation(ctx, base_risk, cfg, "redis_risk_error")
                return
            end
        else
            -- No state change required.
            committed_update = true
        end

        if committed_update then break end
    end
    if not committed_update then
        ngx.log(ngx.ERR, "[RISK] CAS retries exhausted ip=", ip)
        redis_helper.close(red)
        decide_without_reputation(ctx, base_risk, cfg, "redis_risk_contention")
        return
    end
    redis_helper.close(red)

    -- Log chi tiết (Forensics) - Nên bọc lại để không log rác với traffic sạch
    if final_risk >= 0.01 then
        ngx.log(ngx.INFO,
            "[RISK] ip=", ip,
            " base=", string.format("%.1f", base_risk),
            " rep=", string.format("%.1f", reputation),
            " bonus=", bonus,
            " final=", string.format("%.1f", final_risk),
            " signals=[", table.concat(signals, ","), "]"
        )
    end

    -- ── DECISION (Quyết định hành động) ───────────────────────
    -- ACTION CORE: Phán quyết cuối cùng của Risk Engine.
    if final_risk >= cfg.block_threshold then
        ngx.log(ngx.WARN, "[RISK] BLOCK ip=", ip, " final=", string.format("%.1f", final_risk), " signals=[", table.concat(signals, ","), "]")

        ctx.security.risk_action = "block"

        -- Định nghĩa biến local ở đây để tránh lỗi nil
        local attack_types_str = table.concat(signals, ", ")
        if attack_types_str == "" then attack_types_str = "unknown" end

        -- Trực tiếp bắn Alert qua Telegram ngay khi một IP đạt ngưỡng Block.
        telegram_alert.send({
            ip = ip,
            attack_type = attack_types_str,
            score = final_risk,
            reason = "Tạm chặn vì tín hiệu tấn công và điểm rủi ro cao",
            details = "signals=" .. attack_types_str
        })

    elseif final_risk >= cfg.limit_threshold then
        ngx.log(ngx.WARN, "[RISK] LIMIT ip=", ip, " final=", string.format("%.1f", final_risk))
        ctx.security.risk_action = "limit"
    end

    ctx.security.risk_final = final_risk

    -- Đẩy kết quả từ Lua ra biến Nginx để file access.log ghi nhận được
    -- mà không làm lộ dữ liệu qua HTTP Response Header
    -- Rất quan trọng để tích hợp với các hệ thống phân tích Log tập trung (ELK, Datadog...)
    ngx.var.log_risk_score = string.format("%.1f", final_risk)
    ngx.var.log_security_block = ctx.security.risk_action or "pass"

end

return _M
