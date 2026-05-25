-- =============================================================================
-- File: nginx/lua/brute_force_login.lua
-- Chức năng: Chống Brute-force Login thông minh
-- - Theo dõi failed login attempts per IP
-- - Phạt Risk Score cho những IP vượt ngưỡng 5 lần sai mật khẩu trong vòng 5 phút
-- - Trả về 429/403 tùy theo mức độ Risk
-- =============================================================================

local _M = {}
local redis_helper = require "redis_helper"
local ngx = ngx
local tonumber = tonumber
local string = string
local math = math

-- ============================================================
-- CONFIG
-- ============================================================
local function get_config()
    return {
        max_attempts = tonumber(os.getenv("BRUTE_FORCE_MAX_ATTEMPTS")) or 5,
        window_time = tonumber(os.getenv("BRUTE_FORCE_WINDOW")) or 300,       -- 5 phút
        risk_penalty = tonumber(os.getenv("BRUTE_FORCE_RISK_PENALTY")) or 80, -- +80 điểm risk
        cooldown_time = tonumber(os.getenv("BRUTE_FORCE_COOLDOWN")) or 3600,  -- 1 giờ lockout
    }
end

-- ============================================================
-- HELPER: UPDATE RISK REPUTATION THÊM VÀO REDIS
-- ============================================================
local function add_risk_reputation(ip, amount, red)
    if not ip or not amount then
        return
    end

    amount = tonumber(amount) or 0
    if amount <= 0 then
        return
    end

    local key = "risk:v1:" .. ip
    local current = 0
    local existing = red:get(key)
    if existing and existing ~= ngx.null then
        current = tonumber(existing) or 0
    end

    local new_score = math.min(current + amount, 100)
    -- [CRITICAL FIX] Khi score >= 80, set TTL = 1 năm (vĩnh viễn block)
    local ttl = 86400  -- Mặc định 24 giờ
    if new_score >= 80 then
        ttl = 31536000  -- 1 năm = block vĩnh viễn, admin phải xóa thủ công
    end
    red:set(key, string.format("%.2f", new_score), "EX", ttl)
    ngx.log(ngx.WARN, "[BRUTE_FORCE] Risk reputation updated for IP ", ip, ": ", current, " -> ", new_score, " (TTL=", ttl, "s)")
end

-- ============================================================
-- HELPER: THÊM IP VÀO BLACKLIST TEMPORARY
-- ============================================================
local function add_ip_to_blacklist(ip, red)
    if not ip or not red then
        return
    end

    local blacklist_key = "blacklist:" .. ip
    -- [CRITICAL FIX] Khi brute-force block, blacklist = vĩnh viễn (1 năm)
    local bl_ttl = 31536000  -- 1 năm = vĩnh viễn block
    red:set(blacklist_key, "1", "EX", bl_ttl)

    if ngx.shared.ip_cache then
        ngx.shared.ip_cache:set("bl:" .. ip, 1, math.min(bl_ttl, 3600))
    end

    ngx.log(ngx.WARN, "[BRUTE_FORCE] IP " .. ip .. " added to PERMANENT blacklist (" .. tostring(bl_ttl) .. "s - 1 year)")
end

-- ============================================================
-- HELPER: LẤY THÔNG TIN LOGIN TỪ REQUEST
-- ============================================================
local function extract_login_info(ctx)
    -- Đọc request body từ ngx.req.get_body_data()
    local body = ngx.req.get_body_data()
    if not body then
        ngx.req.read_body()
        body = ngx.req.get_body_data()
    end

    if not body then return nil end

    -- Parse form-urlencoded (email=abc@gmail.com&password=xxxxx)
    local email = body:match("email=([^&]*)")
    local password = body:match("password=([^&]*)")

    if email and password then
        -- URL decode
        email = (email:gsub("%%(%x%x)", function(c)
            return string.char(tonumber(c, 16))
        end))
    end

    return { email = email, password = password }
end

-- ============================================================
-- [NEW] HELPER: TRACK PERSISTENT ATTEMPTS ACROSS WINDOWS
-- Mục đích: Ghi nhận lịch sử brute-force để prevent reset exploit
-- ============================================================
local function track_persistent_attempt(ip, attempt_count, red)
    local cfg = get_config()
    local history_key = "brute_force:history:" .. ip
    
    -- [FIX LỖI CHÍ MẠNG]: Xử lý an toàn biến ngx.null của Redis
    local history = red:get(history_key)
    if not history or history == ngx.null then
        history = ""
    end
    
    local new_entry = ngx.now() .. ":" .. attempt_count
    if history == "" then
        history = new_entry
    else
        history = new_entry .. "," .. history
        -- Cắt bớt nếu quá dài
        local entries = {}
        for entry in history:gmatch("[^,]+") do
            table.insert(entries, entry)
            if #entries >= 10 then break end
        end
        history = table.concat(entries, ",")
    end
    
    -- Lưu history với TTL = 24 giờ (enterprise security standard)
    red:set(history_key, history, "EX", 86400)
    
    ngx.log(ngx.DEBUG, "[BRUTE_FORCE] History tracked for IP ", ip, 
            " - entry: ", new_entry)
end

-- ============================================================
-- HELPER: KIỂM TRA IP BỊ LOCKOUT (Cooldown)
-- ============================================================
local function is_ip_locked(ip, ctx)
    local cfg = get_config()
    local red, err = redis_helper.get_redis(0)
    
    if not red then
        ngx.log(ngx.WARN, "[BRUTE_FORCE] Redis unavailable: ", err)
        return false
    end

    local lock_key = "brute_force:lockout:" .. ip
    local locked = red:get(lock_key)
    redis_helper.close(red)

    return (locked and locked ~= ngx.null) and true or false
end

-- ============================================================
-- HELPER: LƯỚI NHỚ CACHE NGẮN HẠN (L1 Cache)
-- ============================================================
local function get_local_cache()
    return ngx.shared.brute_force_cache or ngx.shared.rl_counter
end

-- ============================================================
-- MAIN: SỰ KIỆN LOGIN THẤT BẠI
-- [NEW] Graduated Penalty: 3-strike warning system
-- ============================================================
function _M.record_failed_attempt(ctx)
    local cfg = get_config()
    local ip = ctx.client_ip or ngx.var.realip_remote_addr or ngx.var.remote_addr
    
    -- Kiểm tra IP bị lockout
    if is_ip_locked(ip, ctx) then
        ctx.brute_force = ctx.brute_force or {}
        ctx.brute_force.is_locked = true
        ctx.brute_force.action = "lockout"
        ngx.log(ngx.WARN, "[BRUTE_FORCE] IP ", ip, " is in cooldown (locked)")
        return true
    end

    local red, err = redis_helper.get_redis(0)
    if not red then
        ngx.log(ngx.WARN, "[BRUTE_FORCE] Redis unavailable: ", err)
        ctx.brute_force = { action = "pass" }
        return false
    end

    -- Tăng counter
    local fail_key = "brute_force:fail:" .. ip
    local attempt_count = red:incr(fail_key)
    
    -- Set TTL cho lần đầu (mặc định 15 phút)
    if attempt_count == 1 then
        red:expire(fail_key, cfg.window_time)
    end
    
    -- [FIX] Nếu vượt ngưỡng 5 lần, kéo dài TTL = lockout duration
    -- Điều này prevent IP từ reset counter giữa các window
    if tonumber(attempt_count) >= cfg.max_attempts then
        red:expire(fail_key, cfg.cooldown_time)
    end

    ctx.brute_force = ctx.brute_force or {}
    ctx.brute_force.attempt_count = tonumber(attempt_count) or 0
    ctx.brute_force.max_attempts = cfg.max_attempts

    -- Log
    ngx.log(ngx.WARN, "[BRUTE_FORCE] Failed login for IP ", ip, 
            " - attempt: ", attempt_count, "/", cfg.max_attempts)

    -- [NEW] Track persistent history
    track_persistent_attempt(ip, attempt_count, red)

    -- ============================================================
    -- [NEW] GRADUATED PENALTY SYSTEM
    -- ============================================================
    if tonumber(attempt_count) == 3 then
        -- Lần 3: Phát hiện pattern => Cảnh báo
        ctx.brute_force.action = "warn_level_1"
        ctx.brute_force.challenge = true
        
        ctx.security = ctx.security or {}
        ctx.security.signals = ctx.security.signals or {}
        table.insert(ctx.security.signals, "brute_force_warning:3_attempts")
        
        ngx.log(ngx.WARN, "[BRUTE_FORCE] 3-strike warning for IP ", ip, 
                " - consider adding CAPTCHA or 2FA")
                
    elseif tonumber(attempt_count) == 4 then
        -- Lần 4: Phạt +10 risk điểm (light penalty)
        ctx.brute_force.action = "warn_level_2"
        ctx.brute_force.challenge = true
        
        local risk_penalty = 10
        ctx.security = ctx.security or {}
        ctx.security.risk = (ctx.security.risk or 0) + risk_penalty
        ctx.security.signals = ctx.security.signals or {}
        table.insert(ctx.security.signals, "brute_force_warning:4_attempts")
        
        ngx.log(ngx.WARN, "[BRUTE_FORCE] 4-strike penalty for IP ", ip, 
                " - +", risk_penalty, " risk points")
                
    elseif tonumber(attempt_count) >= cfg.max_attempts then
        -- Lần 5+: Phạt +80 risk điểm + Lockout vĩnh viễn
        ctx.brute_force.action = "block"
        ctx.brute_force.exceed = true
        ctx.brute_force.block_now = true
        
        local risk_penalty = cfg.risk_penalty
        ctx.security = ctx.security or {}
        ctx.security.risk = (ctx.security.risk or 0) + risk_penalty
        ctx.security.signals = ctx.security.signals or {}
        table.insert(ctx.security.signals, "brute_force_attempt:" .. attempt_count)

        -- [CRITICAL FIX] Set cooldown lockout = 1 năm (vĩnh viễn block)
        local lockout_key = "brute_force:lockout:" .. ip
        local permanent_ttl = 31536000  -- 1 năm
        red:set(lockout_key, "1", "EX", permanent_ttl)

        -- Thêm IP vào blacklist tạm thời để các module blacklist bắt được ngay
        add_ip_to_blacklist(ip, red)

        -- Cập nhật risk reputation để những request sau cũng chịu ảnh hưởng
        add_risk_reputation(ip, risk_penalty, red)

        ngx.log(ngx.ALERT, "[BRUTE_FORCE] IP ", ip, 
                " exceeded max attempts! PERMANENT BAN applied (+", risk_penalty, 
                " risk points). Lockout for ", permanent_ttl, "s (1 year)")
    else
        ctx.brute_force.action = "pass"
    end

    redis_helper.close(red)
    return false
end

-- ============================================================
-- MAIN: SỰ KIỆN LOGIN THÀNH CÔNG
-- [FIX] Không reset counter ngay! Chỉ đánh dấu "success" để tracking
-- ============================================================
function _M.record_successful_login(ctx)
    local ip = ctx.client_ip or ngx.var.realip_remote_addr or ngx.var.remote_addr
    
    local red, err = redis_helper.get_redis(0)
    if not red then
        ngx.log(ngx.WARN, "[BRUTE_FORCE] Redis unavailable: ", err)
        return
    end

    -- Không xóa fail counter! Chỉ ghi nhận success time
    -- Điều này cho phép tracking: "Người này từng sai nhiều, nhưng lần này thành công"
    local fail_key = "brute_force:fail:" .. ip
    local success_key = "brute_force:success:" .. ip
    
    -- Lưu timestamp thành công (TTL = window time)
    red:set(success_key, ngx.now(), "EX", get_config().window_time)
    
    redis_helper.close(red)
    
    ngx.log(ngx.INFO, "[BRUTE_FORCE] Successful login for IP ", ip, 
            " (attempt counter preserved for monitoring)")
end

-- ============================================================
-- HELPER: CLEAR COUNTER (Chỉ khi hết window time - do Redis TTL tự làm)
-- ============================================================
function _M.clear_failed_attempts(ctx)
    -- [DEPRECATED - Không dùng nữa]
    -- Counter sẽ tự xóa khi hết TTL từ Redis
    -- Việc gọi hàm này là vô ích vì sẽ tạo lỗ hổng
    ngx.log(ngx.INFO, "[BRUTE_FORCE] Auto-clear by Redis TTL (not manual)")
end

-- ============================================================
-- CHECK: SỰ KIỆN PRE-LOGIN (Trước khi người dùng gửi form)
-- ============================================================
function _M.check_prelogin(ctx)
    local ip = ctx.client_ip or ngx.var.realip_remote_addr or ngx.var.remote_addr
    
    -- Kiểm tra xem IP có đang bị lockout không
    if is_ip_locked(ip, ctx) then
        ctx.brute_force = ctx.brute_force or {}
        ctx.brute_force.action = "block_prelogin"
        ctx.brute_force.is_locked = true
        ngx.log(ngx.WARN, "[BRUTE_FORCE] IP ", ip, " attempted access to login during lockout")
        return true
    end

    return false
end

-- ============================================================
-- EXPORT
-- ============================================================
return _M
