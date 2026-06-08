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
        -- [NEW] Cơ chế Decay: Giảm dần reputation score theo thời gian.
        -- Mục đích: Tránh việc chặn vĩnh viễn các IP NAT/CGNAT chia sẻ (nhiều user dùng chung 1 IP).
        -- RISK_DECAY_ENABLED=true  : Bật decay (khuyến nghị cho production có NAT)
        -- RISK_DECAY_ENABLED=false : Tắt decay - No-Forgiveness policy (strict, chỉ dùng khi chắc chắn user-level IP)
        decay_enabled = (os.getenv("RISK_DECAY_ENABLED") or "false"):lower() == "true",
        -- Hệ số giảm: 0.1 = giảm 10% reputation hiện tại mỗi lần IP gửi request sạch
        -- Ví dụ: reputation=60 + clean request → 60 * (1-0.1) = 54
        decay_factor = tonumber(os.getenv("RISK_DECAY_FACTOR")) or 0.1,
    }
end

local DECAY_FACTOR = 0.9
local MAX_RISK     = 100

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

    -- ── REDIS REPUTATION ──────────────────────────────────────
    -- Kết nối an toàn qua Helper (Tự động Select DB 0)
    local red, err = redis_helper.get_redis(0)

    if not red then
        ngx.log(ngx.WARN, "[RISK] Redis unavailable: ", err)
        -- Fallback Graceful
        if base_risk >= cfg.block_threshold then
            ctx.security.risk_action = "block"
        elseif base_risk >= cfg.limit_threshold then
            ctx.security.risk_action = "limit"
        end
        ctx.security.risk_final = base_risk
        return
    end

    -- Lấy "Điểm uy tín" (Reputation) lịch sử của IP từ Redis.
    local key = "risk:v1:" .. ip
    local reputation = red:get(key)
    reputation = (reputation and reputation ~= ngx.null) and tonumber(reputation) or 0

    -- Clamp (Chốt chặn max) ngay tại từng bước tính toán để logic rõ ràng
    -- Cơ chế DECAY: Nếu request hiện tại sạch (base_risk = 0) và IP này không
    -- trong permanent ban, áp dụng hệ số decay để giảm dần reputation theo thời gian.
    -- Mục đích: Tránh chặn vĩnh viễn các IP NAT/CGNAT mà nhiều user dùng chung.
    if cfg.decay_enabled and base_risk == 0 and reputation < cfg.block_threshold then
        -- Chỉ decay khi request sạch hoàn toàn và chưa đạt ngưỡng permanent ban
        reputation = reputation * (1 - cfg.decay_factor)
        if reputation < 1 then reputation = 0 end  -- Floor về 0 khi gần sạch
        ngx.log(ngx.INFO, "[RISK] DECAY applied for ip=", ip,
            " reputation=", string.format("%.2f", reputation),
            " (factor=", cfg.decay_factor, ")")
    end

    local final_risk = math_min(reputation + base_risk, MAX_RISK)
    
    -- Nếu đã permanent ban (reputation >= 80), giữ nguyên 80 (không nhân bất kỳ hệ số)
    if reputation >= cfg.block_threshold then
        final_risk = reputation
        ngx.log(ngx.WARN, "[RISK] PERMANENT_BAN detected for IP ", ip, " - reputation=", reputation, " (no decay, no forgiveness)")
    end

    -- =========================================================================
    -- BRUTE-FORCE REPUTATION TRACKING
    -- Kiểm tra lịch sử brute-force để accumulate risk across windows
    -- =========================================================================
    local bf_history_key = "brute_force:history:" .. ip
    local bf_history = red:get(bf_history_key)
    
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
    -- Nhưng nếu reputation >= 80 (permanent ban), không thêm điểm nữa
    if base_risk > 50 and reputation < cfg.block_threshold then
        final_risk = math_min(final_risk + 10, MAX_RISK)
    end

    -- =========================================================================
    -- TỐI ƯU HÓA REDIS WRITE I/O
    -- Chỉ thực hiện ghi xuống Redis nếu:
    -- 1. IP này vừa gây ra rủi ro (final_risk > 0.01)
    -- 2. Hoặc IP này đang có "tiền án" và cần cập nhật lại điểm số (reputation > 0.01)
    -- Nếu cả hai đều = 0 (Người dùng hoàn toàn sạch), BỎ QUA lệnh ghi!
    -- =========================================================================
    if final_risk >= 0.01 or reputation >= 0.01 then
        
        -- Trừng phạt theo cấp độ - Kẻ càng nguy hiểm bị nhớ càng lâu
        -- Khi block (>= 80), TTL = 1 năm (vĩnh viễn block)
        -- Dynamic TTL: Mức độ rủi ro quyết định thời gian IP bị lưu trữ.
        -- Đạt 80 điểm -> Lưu vào Redis 1 năm (Ban vĩnh viễn cấp Database).
        local rep_ttl = 3600 -- Mặc định 1 giờ
        if final_risk >= cfg.block_threshold then
            rep_ttl = 31536000  -- Bị Block: Ghi nhớ 1 năm
        elseif final_risk >= cfg.limit_threshold then
            rep_ttl = 7200   -- Bị Limit: Ghi nhớ 2 giờ
        end

        -- Ghi điểm Uy tín mới vào Redis
        red:set(key, string.format("%.2f", final_risk), "EX", rep_ttl)

        -- Nếu block (final_risk >= 80), cũng thêm IP vào blacklist permanent
        -- Đồng bộ chéo với Blacklist. Hệ thống sẽ chặn ngay từ lớp ngoài cùng
        -- ở các request kế tiếp, không cần phải chạy lại toàn bộ chain Security nữa.
        if final_risk >= cfg.block_threshold then
            red:sadd("blacklist_ips", ip)
            local bl_key = "blacklist:" .. ip
            red:set(bl_key, "1", "EX", rep_ttl)
            ngx.log(ngx.WARN, "[RISK] IP BLACKLISTED permanently ip=", ip, " final_risk=", string.format("%.1f", final_risk), " TTL=", rep_ttl, "s")
        end
    end
    
    -- Luôn nhớ đóng kết nối Redis để trả về Pool, tránh tràn RAM
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
        if metric_blocked then metric_blocked:inc(1, {"risk_block"}) end
        
        ctx.security.risk_action = "block"
        
        -- Định nghĩa biến local ở đây để tránh lỗi nil
        local attack_types_str = table.concat(signals, ", ")
        if attack_types_str == "" then attack_types_str = "unknown" end
        
        -- Trực tiếp bắn Alert qua Telegram ngay khi một IP đạt ngưỡng Block.
        telegram_alert.send({
            ip = ip,
            attack_type = attack_types_str,
            score = final_risk,
            reason = "Khóa vĩnh viễn vì hành vi tấn công trái phép",
            details = "signals=" .. attack_types_str
        })

    elseif final_risk >= cfg.limit_threshold then
        ngx.log(ngx.WARN, "[RISK] LIMIT ip=", ip, " final=", string.format("%.1f", final_risk))
        if metric_blocked then metric_blocked:inc(1, {"risk_limit"}) end
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