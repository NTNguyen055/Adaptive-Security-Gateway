local _M = {}
local limit_req = require "resty.limit.req"
local tonumber = tonumber

-- ============================================================
-- CONFIG & LIMITER INIT
-- ============================================================
local function get_config()
    return {
        rate         = tonumber(os.getenv("RATE_LIMIT_RPS"))     or 10,
        burst        = tonumber(os.getenv("RATE_LIMIT_BURST"))   or 20,
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
-- MAIN
-- ============================================================
function _M.run(ctx)
    local limiter = get_limiter()
    if not limiter then return end

    local ip = (ctx.security and ctx.security.client_ip)
               or ngx.var.remote_addr
               or ngx.var.realip_remote_addr

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

    -- REJECTED
    if not delay then
        if err == "rejected" then
            ctx.security.rate_limit_hard = true
            ctx.security.block = true

            table.insert(ctx.security.signals, "rate_limit_hard")

            ngx.log(ngx.WARN, "[RATE_LIMIT] HARD Block ip=", ip)
            return
        end

        ngx.log(ngx.ERR, "[RATE_LIMIT] Error: ", err)
        return
    end

    -- BURST
    if delay > 0 then
        ctx.security.rate_limit_burst = true
        ctx.security.block = true

        table.insert(ctx.security.signals, "rate_limit_burst")

        ngx.log(
            ngx.WARN,
            "[RATE_LIMIT] BURST Block ip=",
            ip,
            " delay_ms=",
            string.format("%.0f", delay * 1000)
        )
        return
    end
end

return _M
