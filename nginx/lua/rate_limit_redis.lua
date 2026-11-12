local _M = {}

local ngx        = ngx
local tonumber   = tonumber
local math_floor = math.floor
local redis_helper = require "redis_helper" -- Gọi module dùng chung (Tránh lỗi DB 0)

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
-- REDIS SCRIPT (Sliding Window cực kỳ chính xác)
-- Sử dụng ZSET thay cho INCR, khắc phục lỗi Boundary Spike
-- ============================================================
-- CORE ALGORITHM: Khác với dùng lệnh INCR thông thường (Fixed Window) dễ bị lỗi 
-- "Boundary Spike" (Ví dụ: Gửi 30 request ở giây 59 và 30 request ở giây 01 -> Hệ thống nhận 60 request 
-- chỉ trong 2 giây nhưng không block do khác phút).
-- Thuật toán này dùng Sorted Set (ZSET) với điểm score chính là thời gian (timestamp ms).
-- Mọi request cũ hơn (now - window) sẽ bị vứt bỏ, giúp đếm rate limit trượt theo thời gian thực cực kỳ mượt mà.
local SLIDING_SCRIPT = [[
local key        = KEYS[1]
local seq_key    = KEYS[2]
local now_ms     = tonumber(ARGV[1])
local window_ms  = tonumber(ARGV[2]) * 1000

-- Loại bỏ request nằm ngoài sliding window.
redis.call(
    'ZREMRANGEBYSCORE',
    key,
    '-inf',
    now_ms - window_ms
)

-- INCR chạy nguyên tử trong Redis.
-- Đảm bảo các request cùng mili-giây có member riêng.
local seq = redis.call('INCR', seq_key)
local member = tostring(now_ms) .. ':' .. tostring(seq)

redis.call('ZADD', key, now_ms, member)

-- Tự động dọn dẹp cả ZSET và sequence key.
redis.call('PEXPIRE', key, window_ms)
redis.call('PEXPIRE', seq_key, window_ms)

return redis.call('ZCARD', key)
]]

-- ============================================================
-- MAIN
-- ============================================================
function _M.run(ctx)
    local ip  = (ctx.security and ctx.security.client_ip)
                or ngx.var.remote_addr
                or ngx.var.realip_remote_addr
    local uri = ngx.var.uri or ""

    ctx.security         = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    local cfg = get_config()

    -- Mỗi request đến Redis Rate Limiter phải được ghi nhận.
    -- Không dùng micro-cache để bỏ qua việc đếm request.
    -- Local Rate Limiter phía trước vẫn giữ chức năng bảo vệ L1.

    -- ── REDIS (L2 Cache) ──────────────────────────────────────
    -- Kết nối an toàn qua Helper (Tự động Select DB 0)
    local red, err = redis_helper.get_redis(0)

    if not red then
        ngx.log(ngx.WARN, "[REDIS_RL] Redis unavailable: ", err)

        -- Infrastructure failure is not evidence of client abuse.
        -- Local Rate Limiting remains active as a fallback.
        ctx.security.redis_rl_fail = true
        return
    end

    -- Lấy thời gian chính xác tới từng Mili-giây để truyền cho Redis ZSET
    local now_ms     = math_floor(ngx.now() * 1000)
    local key_ip     = "rrl:" .. ip
    local key_ip_uri = "rrl:" .. ip .. ":" .. uri

    -- TỐI ƯU I/O: Sử dụng Pipeline để gom cụm (batching). Thay vì gửi 2 network round-trip 
    -- tới Redis (1 cho IP tổng, 1 cho IP+URI) thì gói gọn lại thành 1 gói duy nhất. Giảm 50% độ trễ (latency).
    red:init_pipeline()
    red:eval(
        SLIDING_SCRIPT, 2,
        key_ip, key_ip .. ":seq",
        now_ms, cfg.window
    )

    red:eval(
        SLIDING_SCRIPT, 2,
        key_ip_uri, key_ip_uri .. ":seq",
        now_ms, cfg.window
    )

    local results, pipe_err = red:commit_pipeline()

    -- Lỗi truyền dữ liệu: không tái sử dụng kết nối.
    if not results then
        red:close()

        ngx.log(
            ngx.ERR,
            "[REDIS_RL] Pipeline failed: ",
            tostring(pipe_err)
        )

        ctx.security.redis_rl_error = true
        return
    end

    redis_helper.close(red)

    -- Redis EVAL trả về integer khi thành công.
    -- Không được coi phản hồi lỗi là số đếm bằng 0.
    local function valid_count(value)
        return type(value) == "number"
            and value >= 1
            and value % 1 == 0
    end

    if #results ~= 2
        or not valid_count(results[1])
        or not valid_count(results[2]) then

        ctx.security.redis_rl_error = true

        ngx.log(
            ngx.ERR,
            "[REDIS_RL] Invalid pipeline replies ip=",
            ip
        )

        return
    end

    local count_ip = results[1]
    local count_ip_uri = results[2]
    
    -- Kiểm tra Độc lập. Không dùng math.max sai lầm nữa.
    -- Giới hạn cho 1 URI cụ thể sẽ chặt hơn (chỉ bằng 70% tổng giới hạn IP)
    -- Phân chia giới hạn: Một User được phép gửi 30 req/phút toàn hệ thống, 
    -- nhưng KHÔNG ĐƯỢC phép dồn 30 req đó vào đúng 1 endpoint duy nhất (vd: liên tục spam API /login). 
    -- Endpoint cụ thể chỉ được chịu tối đa 70% giới hạn tổng.
    local limit_global = cfg.limit
    local limit_uri    = math_floor(limit_global * 0.7)

    -- ── EXCEEDED (>100%) ──────────────────────────────────────
    if count_ip > limit_global or count_ip_uri > limit_uri then
    -- Chỉ từ chối request hiện tại khi vượt Redis Rate Limit.
    -- Không cộng Risk hoặc tự động blacklist IP chỉ vì vượt tốc độ.
    -- Risk Engine sẽ phân loại request này là rate-only mitigation.
        ctx.security.redis_rate_exceeded = true
        ctx.security.block               = true

        table.insert(ctx.security.signals, "redis_rate_exceeded")
        ngx.log(ngx.WARN, "[REDIS_RL] EXCEEDED ip=", ip, " count_ip=", count_ip, "/", limit_global, " count_uri=", count_ip_uri, "/", limit_uri)

        return
    end

    -- ── WARNING (70%~100%) ────────────────────────────────────
    -- Gần chạm giới hạn chưa phải bằng chứng tấn công.
    -- Chỉ ghi nhận tín hiệu để quan sát, không tăng Risk Score.
    if count_ip > (limit_global * 0.7)
        or count_ip_uri > (limit_uri * 0.7) then

        ctx.security.redis_rate_warn = true

        table.insert(ctx.security.signals, "redis_rate_warn")

        ngx.log(
            ngx.WARN,
            "[REDIS_RL] WARN ip=", ip,
            " count_ip=", count_ip, "/", limit_global,
            " count_uri=", count_ip_uri, "/", limit_uri
        )

        return
    end

end

return _M
