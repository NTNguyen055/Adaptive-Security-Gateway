local _M = {}
local limit_req = require "resty.limit.req"
local redis_helper = require "redis_helper" -- [THÊM MỚI] Gọi helper Redis
local math_min = math.min
local tonumber = tonumber

-- ============================================================
-- CONFIG & LIMITER INIT
-- ============================================================
local function get_config()
    return {
        rate         = tonumber(os.getenv("RATE_LIMIT_RPS"))     or 10,
        burst        = tonumber(os.getenv("RATE_LIMIT_BURST"))   or 20,
        bl_threshold = tonumber(os.getenv("AUTO_BL_THRESHOLD"))  or 5,
        bl_window    = tonumber(os.getenv("AUTO_BL_WINDOW"))     or 60,
        bl_duration  = tonumber(os.getenv("AUTO_BL_DURATION"))   or 3600,
    }
end

-- Limiter Cache được lưu trữ ở cấp độ Worker
-- LƯU Ý CHO ADMIN: Khi thay đổi thông số RATE_LIMIT_RPS trong .env, 
-- phải chạy lại `docker-compose up -d --force-recreate gateway` để worker tải lại cache.
local _limiter_cache = nil

local function get_limiter()
    -- CORE HIỆU NĂNG: Khởi tạo Limiter (Token Bucket) 1 lần duy nhất cho mỗi 
    -- Nginx Worker Process và lưu vào biến toàn cục của script Lua (tương đương cấp Worker).
    -- Điều này giúp hệ thống không tốn chi phí rà soát bộ nhớ chia sẻ ở mỗi request.
    if _limiter_cache then return _limiter_cache end

    local cfg = get_config()
    local l, err = limit_req.new("limit_req_store", cfg.rate, cfg.burst)
    
    if not l then
        ngx.log(ngx.ERR, "[RATE_LIMIT] Init failed: ", err)
        return nil
    end

    _limiter_cache = l
    return _limiter_cache
end

-- ============================================================
-- AUTO BLACKLIST (Async Timer)
-- ============================================================
local function auto_blacklist(ip, ctx)
    local cfg = get_config()
    local counter_store = ngx.shared.rl_counter
    if not counter_store then return end

    -- Đếm số lần IP này bị giới hạn rate limit trong 1 cửa sổ thời gian (60 giây).
    local count = counter_store:incr("rl:" .. ip, 1, 0, cfg.bl_window)
    if not count then return end

    -- Sửa logic AND thành OR để chặn Spam thuần túy
    -- Một IP spam sẽ bị chặn nếu VƯỢT THRESHOLD, 
    -- HOẶC nếu chưa vượt ngưỡng nhưng điểm Risk >= 50
    -- CORE: Liên kết với module Risk Engine. Nếu IP này vừa spam request, 
    -- vừa có những hành vi xấu (Bad Bot, VPN, Tor) làm điểm rủi ro cao -> Chặn thẳng tay dù chưa tới ngưỡng threshold.
    local should_block = (count >= cfg.bl_threshold) 
                      or (count >= 2 and (ctx.security.risk or 0) >= 50)
                      
    if not should_block then return end

    -- Lock để tránh chạy nhiều luồng ghi Redis cùng lúc
    -- Race Condition Preventer: Khi IP bị tấn công bằng hàng nghìn luồng (threads), 
    -- hàm này được gọi liên tục. `add` đảm bảo chỉ luồng chạy đầu tiên mới được phép chọc xuống Redis (L2).
    local lock = counter_store:add("bl_lock:" .. ip, 1, 5)
    if not lock then return end

    -- Ghi nhận blacklist vào RAM cục bộ của Worker hiện tại (L1)
    -- Cập nhật ngay vào cache bộ nhớ chia sẻ của Nginx để ngắt mạch (Circuit Breaker) lập tức.
    local bl_cache = ngx.shared.ip_cache -- Đã đồng bộ tên cache với nginx.conf
    if bl_cache then
        bl_cache:set("bl:" .. ip, 1, cfg.bl_duration)
    end

    -- Bắn Async job lên Redis để thông báo cho các Worker khác (L2)
    -- Nginx xử lý theo mô hình hướng sự kiện (Event-driven). Đẩy tác vụ ghi Redis 
    -- vào Timer nền (ngx.timer) để không chặn (block) request hiện tại của người dùng.
    ngx.timer.at(0, function(premature, target_ip, duration, risk_score)
        if premature then return end

        -- FIX 3: Sử dụng redis_helper để có timeout chuẩn và tự động chọn DB 0
        local red, err = redis_helper.get_redis(0)
        if not red then
            ngx.log(ngx.ERR, "[AUTO_BL] Redis connect failed: ", err)
            return
        end

        local key = "blacklist:" .. target_ip
        -- [CRITICAL FIX] Nếu risk_score >= 50, blacklist = vĩnh viễn (1 năm)
        local final_ttl = duration
        if risk_score and risk_score >= 50 then
            final_ttl = 31536000  -- 1 năm = vĩnh viễn block
        end
        -- Đồng bộ Blacklist lên Redis. Các Nginx node khác trong Cluster 
        -- sẽ nhận biết được IP này và cùng chặn.
        red:set(key, "1")
        red:expire(key, final_ttl)

        redis_helper.close(red)
        ngx.log(ngx.WARN, "[AUTO_BL] BLACKLISTED ip=", target_ip, " duration=", final_ttl, "s (risk=", risk_score, ")")
    end, ip, cfg.bl_duration, ctx.security.risk or 0)

    -- Xóa biến đếm để khỏi bị Trigger lặp lại
    counter_store:delete("rl:" .. ip)
end

-- ============================================================
-- MAIN
-- ============================================================
function _M.run(ctx)
    local limiter = get_limiter()
    if not limiter then return end

    local ip = (ctx.security and ctx.security.client_ip)
               or ngx.var.realip_remote_addr
               or ngx.var.remote_addr

    -- Chỉ dùng IP làm Key (Bỏ URI)
    -- Lý do: Ngăn chặn Hacker Bypass Limit bằng cách liên tục thay đổi URI request
    -- Giới hạn áp dụng tổng quát cho MỌI endpoint. Hacker có đổi URL ngẫu nhiên
    -- (Ví dụ: /api/1, /api/2) thì IP của hắn vẫn bị cộng dồn và ăn block.
    local key = ip

    ctx.security         = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    -- Đưa IP vào Token Bucket. Hàm `incoming` sẽ đánh giá:
    -- 1. Nếu delay = 0: Request hoàn toàn bình thường.
    -- 2. Nếu delay > 0: Request này vượt Rate (RPS) nhưng vẫn chưa chạm nóc Burst. 
    -- 3. Nếu delay = nil, err = 'rejected': Vượt cả Rate lẫn Burst. Bị Drop.
    local delay, err = limiter:incoming(key, true)

    -- ── REJECTED (Vượt qua ngương Burst) ────────────────────────
    if not delay then
        if err == "rejected" then
            -- ACTION CORE: Kích hoạt Hard Block. Cập nhật thẳng +80 điểm Risk 
            -- để chạm ngưỡng khóa vĩnh viễn của Risk Engine, sau đó ném qua hàm Auto Blacklist.
            ctx.security.rate_limit_hard = true
            ctx.security.block           = true   
            ctx.security.risk            = math_min((ctx.security.risk or 0) + 80, 100)

            table.insert(ctx.security.signals, "rate_limit_hard")
            ngx.log(ngx.WARN, "[RATE_LIMIT] HARD Block ip=", ip)

            auto_blacklist(ip, ctx)
            return
        end

        ngx.log(ngx.ERR, "[RATE_LIMIT] Error: ", err)
        return
    end

    -- ── BURST (Vượt RPS nhưng chưa vượt ngưỡng Burst) ───────────
    if delay > 0 then
        -- Trong ứng dụng thực tế, không Delay (sleep) request vì việc đó 
        -- làm kẹt Worker của Nginx (DDoS tự sát). Thay vào đó, nếu đã chạm vùng Burst thì Block luôn.
        ctx.security.rate_limit_burst = true
        ctx.security.block = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 80, 100)

        table.insert(ctx.security.signals, "rate_limit_burst")
        ngx.log(ngx.WARN, "[RATE_LIMIT] BURST Block ip=", ip, " delay_ms=", string.format("%.0f", delay * 1000))
        auto_blacklist(ip, ctx)
        return
    end

end

return _M