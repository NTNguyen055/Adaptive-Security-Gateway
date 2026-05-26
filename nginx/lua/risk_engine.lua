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
        block_threshold = tonumber(os.getenv("RISK_BLOCK_THRESHOLD")) or 80,
        limit_threshold = tonumber(os.getenv("RISK_LIMIT_THRESHOLD")) or 50,
    }
end

local DECAY_FACTOR = 0.9
local MAX_RISK     = 100

-- ============================================================
-- SIGNAL CORRELATION
-- ============================================================
local SIGNAL_BONUS = {
    -- Đã có
    xff_private_client = 5,
    bad_bot_scanner    = 10,
    geo_block          = 5,
    empty_ua           = 5,
    
    -- FIX 5: Bổ sung các tín hiệu bảo mật cực kỳ nguy hiểm
    jwt_replay         = 15,   -- Đánh cắp Token
    jwt_alg_attack     = 20,   -- Tấn công kỹ thuật bẻ khóa JWT
    waf_xss            = 20,   -- Lỗ hổng nhúng mã JS
    xff_chain_abuse    = 15,   -- Giấu mặt sau nhiều tầng Proxy

    brute_force_attack = 30,  -- Tín hiệu từ brute_force_login.lua
    xff_malformed      = 20,  -- Tín hiệu từ xff_guard.lua
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

    for signal, points in pairs(SIGNAL_BONUS) do
        if signal_set[signal] then
            bonus = bonus + points
        end
    end

    -- FIX 6: Mở rộng các combo nguy hiểm (Combination Bonus)
    if signal_set["waf_sqli"] and signal_set["bad_bot_scanner"] then bonus = bonus + 15 end
    if signal_set["rate_limit_hard"] and signal_set["geo_block"] then bonus = bonus + 10 end
    if signal_set["jwt_invalid"] and signal_set["rate_limit_hard"] then bonus = bonus + 10 end
    
    -- Combo mới
    if signal_set["waf_xss"] and signal_set["jwt_missing"] then bonus = bonus + 15 end          -- Tấn công XSS khi chưa đăng nhập
    if signal_set["bad_bot_headless"] and signal_set["waf_sqli"] then bonus = bonus + 20 end    -- Dùng tool tự động để cào Database
    if signal_set["xff_private_client"] and signal_set["jwt_invalid"] then bonus = bonus + 15 end -- Giả mạo IP LAN để phá mật khẩu

    base_risk = math_min(base_risk + bonus, MAX_RISK)

    -- ── REDIS REPUTATION ──────────────────────────────────────
    -- FIX 1: Kết nối an toàn qua Helper (Tự động Select DB 0)
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

    local key = "risk:v1:" .. ip
    local reputation = red:get(key)
    reputation = (reputation and reputation ~= ngx.null) and tonumber(reputation) or 0

    -- FIX 2: Clamp (Chốt chặn max) ngay tại từng bước tính toán để logic rõ ràng
    -- [CRITICAL FIX v2] Không decay - chỉ cộng thêm signal mới
    -- Nếu request sạch (base_risk = 0), giữ nguyên reputation
    -- Nếu có signal mới, cộng thêm vào reputation
    local final_risk = math_min(reputation + base_risk, MAX_RISK)
    
    -- Nếu đã permanent ban (reputation >= 80), giữ nguyên 80 (không nhân bất kỳ hệ số)
    if reputation >= cfg.block_threshold then
        final_risk = reputation
        ngx.log(ngx.WARN, "[RISK] PERMANENT_BAN detected for IP ", ip, " - reputation=", reputation, " (no decay, no forgiveness)")
    end

    -- =========================================================================
    -- [NEW] BRUTE-FORCE REPUTATION TRACKING
    -- Kiểm tra lịch sử brute-force để accumulate risk across windows
    -- =========================================================================
    local bf_history_key = "brute_force:history:" .. ip
    local bf_history = red:get(bf_history_key)
    
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
    -- FIX 7: Tăng ngưỡng lên 50 để tránh phạt oan người dùng chỉ mở F12 (Dev_tool)
    -- [CRITICAL FIX] Nhưng nếu reputation >= 80 (permanent ban), không thêm điểm nữa
    if base_risk > 50 and reputation < cfg.block_threshold then
        final_risk = math_min(final_risk + 10, MAX_RISK)
    end

    -- [CRITICAL FIX v2] NO FORGIVENESS - Giữ nguyên điểm forever
    -- Không bao giờ giảm điểm dù là 0.8x hay bất kỳ hệ số nào
    -- IP càng nguy hiểm bị nhớ càng lâu, không có khoan hồng tự động
    -- final_risk được tính từ reputation + base_risk, giữ nguyên không nhân hệ số

    -- =========================================================================
    -- [FIX HIỆU NĂNG - ENTERPRISE STANDARD]: TỐI ƯU HÓA REDIS WRITE I/O
    -- Chỉ thực hiện ghi xuống Redis nếu:
    -- 1. IP này vừa gây ra rủi ro (final_risk > 0.01)
    -- 2. Hoặc IP này đang có "tiền án" và cần cập nhật lại điểm số (reputation > 0.01)
    -- Nếu cả hai đều = 0 (Người dùng hoàn toàn sạch), BỎ QUA lệnh ghi!
    -- =========================================================================
    if final_risk >= 0.01 or reputation >= 0.01 then
        
        -- FIX 4: Trừng phạt theo cấp độ - Kẻ càng nguy hiểm bị nhớ càng lâu
        -- [CRITICAL FIX] Khi block (>= 80), TTL = 1 năm (vĩnh viễn block)
        local rep_ttl = 3600 -- Mặc định 1 giờ
        if final_risk >= cfg.block_threshold then
            rep_ttl = 31536000  -- Bị Block: Ghi nhớ 1 năm (vĩnh viễn) - Admin phải xóa thủ công
        elseif final_risk >= cfg.limit_threshold then
            rep_ttl = 7200   -- Bị Limit: Ghi nhớ 2 giờ
        end

        -- Ghi điểm Uy tín mới vào Redis
        red:set(key, string.format("%.2f", final_risk), "EX", rep_ttl)

        -- [NEW FIX] Nếu block (final_risk >= 80), cũng thêm IP vào blacklist permanent
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
    if final_risk >= cfg.block_threshold then
        ngx.log(ngx.WARN, "[RISK] BLOCK ip=", ip, " final=", string.format("%.1f", final_risk), " signals=[", table.concat(signals, ","), "]")
        if metric_blocked then metric_blocked:inc(1, {"risk_block"}) end
        
        ctx.security.risk_action = "block"
        
        -- [FIX]: Định nghĩa biến local ở đây để tránh lỗi nil
        local attack_types_str = table.concat(signals, ", ")
        if attack_types_str == "" then attack_types_str = "unknown" end
        
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

    -- [FIX LOG]: Đẩy kết quả từ Lua ra biến Nginx để file access.log ghi nhận được 
    -- mà không làm lộ dữ liệu qua HTTP Response Header
    ngx.var.log_risk_score = string.format("%.1f", final_risk)
    ngx.var.log_security_block = ctx.security.risk_action or "pass"
    
end

return _M