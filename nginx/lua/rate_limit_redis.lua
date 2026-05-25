local _M = {}

local ngx        = ngx
local tonumber   = tonumber
local math_min   = math.min
local math_floor = math.floor
local redis_helper = require "redis_helper" -- FIX 1: Gọi module dùng chung (Tránh lỗi DB 0)

-- ============================================================
-- CONFIG
-- ============================================================
local function get_config()
    return {
        limit  = tonumber(os.getenv("REDIS_RATE_LIMIT")) or 30,
        window = tonumber(os.getenv("REDIS_RL_WINDOW"))  or 60,
    }
end

-- ============================================================
-- REDIS SCRIPT (FIX 2 & 3: Sliding Window cực kỳ chính xác)
-- Sử dụng ZSET thay cho INCR, khắc phục lỗi Boundary Spike
-- ============================================================
local SLIDING_SCRIPT = [[
local key    = KEYS[1]
local now_ms = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local clear_before = now_ms - (window * 1000)

-- Xóa các request đã quá hạn (ngoài cửa sổ) khỏi ZSET
redis.call('ZREMRANGEBYSCORE', key, 0, clear_before)
-- Thêm thời điểm request hiện tại vào ZSET
redis.call('ZADD', key, now_ms, now_ms)
-- Đặt TTL để Redis tự dọn rác nếu không còn ai truy cập
redis.call('EXPIRE', key, window)

-- Trả về tổng số request hợp lệ đang có trong ZSET
return redis.call('ZCARD', key)
]]

-- ============================================================
-- MAIN
-- ============================================================
function _M.run(ctx)
    local ip  = (ctx.security and ctx.security.client_ip)
                or ngx.var.realip_remote_addr
                or ngx.var.remote_addr
    local uri = ngx.var.uri or ""

    ctx.security         = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    local cfg = get_config()

    -- ── LOCAL THROTTLE (L1 Cache) ─────────────────────────────
    local throttle = ngx.shared.rl_counter
    
    -- FIX 4: Không bỏ qua throttle nếu IP đang burst/hard limit
    local skip_throttle = ctx.security.rate_limit_burst or ctx.security.rate_limit_hard

    if throttle and (ctx.security.risk or 0) < 30 and not skip_throttle then
        local throttle_key = "rrl_throttle:" .. ip
        local hit = throttle:get(throttle_key)
        if hit then
            -- FIX 6: Xóa bỏ signal "redis_rate_ok" để làm sạch log
            return
        end
        -- FIX 4: Giảm TTL xuống 0.2s (200ms) thay vì 1s để không che giấu các đợt Burst
        throttle:set(throttle_key, 1, 0.2)  
    end

    -- ── REDIS (L2 Cache) ──────────────────────────────────────
    -- FIX 1: Kết nối an toàn qua Helper (Tự động Select DB 0)
    local red, err = redis_helper.get_redis(0)

    if not red then
        ngx.log(ngx.WARN, "[REDIS_RL] Redis down: ", err)
        ctx.security.redis_rl_fail = true

        local base = ctx.security.rate_limit_hard and 15 or 5
        ctx.security.risk = math_min((ctx.security.risk or 0) + base, 100)
        return
    end

    -- FIX 3: Lấy thời gian chính xác tới từng Mili-giây để truyền cho Redis ZSET
    local now_ms     = math_floor(ngx.now() * 1000)
    local key_ip     = "rrl:" .. ip
    local key_ip_uri = "rrl:" .. ip .. ":" .. uri

    red:init_pipeline()
    red:eval(SLIDING_SCRIPT, 1, key_ip,     now_ms, cfg.window)
    red:eval(SLIDING_SCRIPT, 1, key_ip_uri, now_ms, cfg.window)
    local results, pipe_err = red:commit_pipeline()

    redis_helper.close(red)

    if not results then
        ngx.log(ngx.ERR, "[REDIS_RL] Pipeline error: ", pipe_err)
        ctx.security.redis_rl_error = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 10, 100)
        return
    end

    local count_ip     = tonumber(results[1]) or 0
    local count_ip_uri = tonumber(results[2]) or 0
    
    -- FIX 5: Kiểm tra Độc lập. Không dùng math.max sai lầm nữa.
    -- Giới hạn cho 1 URI cụ thể sẽ chặt hơn (chỉ bằng 70% tổng giới hạn IP)
    local limit_global = cfg.limit
    local limit_uri    = math_floor(limit_global * 0.7)

    -- ── EXCEEDED (>100%) ──────────────────────────────────────
    if count_ip > limit_global or count_ip_uri > limit_uri then
        ctx.security.redis_rate_exceeded = true
        ctx.security.block               = true   
        ctx.security.risk                = math_min((ctx.security.risk or 0) + 80, 100)

        table.insert(ctx.security.signals, "redis_rate_exceeded")
        ngx.log(ngx.WARN, "[REDIS_RL] EXCEEDED ip=", ip, " count_ip=", count_ip, "/", limit_global, " count_uri=", count_ip_uri, "/", limit_uri)

        if metric_blocked then metric_blocked:inc(1, {"redis_rate_limit"}) end
        return
    end

    -- ── WARNING (70%~100%) ────────────────────────────────────
    if count_ip > (limit_global * 0.7) or count_ip_uri > (limit_uri * 0.7) then
        ctx.security.redis_rate_warn = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 10, 100)
        
        table.insert(ctx.security.signals, "redis_rate_warn")
        ngx.log(ngx.WARN, "[REDIS_RL] WARN ip=", ip, " count_ip=", count_ip, "/", limit_global, " count_uri=", count_ip_uri, "/", limit_uri)

        -- FIX 7: Bổ sung Metric để theo dõi lượng User đang mấp mé mép bờ Block
        if metric_blocked then metric_blocked:inc(1, {"redis_rate_warn"}) end
        return
    end

    -- ── NORMAL (<70% limit) ───────────────────────────────────
    -- FIX 6: Đã xóa table.insert(ctx.security.signals, "redis_rate_ok")
end

return _M