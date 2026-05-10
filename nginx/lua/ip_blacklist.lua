local _M = {}
local math_min = math.min
local redis_helper = require "redis_helper" -- [THÊM MỚI] Gọi module dùng chung

-- Giảm thời gian cache để việc gỡ ban (unban) thủ công có tác dụng nhanh hơn
local CACHE_TTL_POSITIVE = 60 
local CACHE_TTL_NEGATIVE = 30

-- ============================================================
-- MAIN
-- ============================================================
function _M.run(ctx)
    -- Ưu tiên dùng client_ip đã normalize từ xff_guard
    local ip = (ctx.security and ctx.security.client_ip)
               or ngx.var.realip_remote_addr
               or ngx.var.remote_addr

    if not ip then return end

    ctx.security         = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    -- Tái sử dụng vùng nhớ ip_cache được khai báo trong nginx.conf
    local cache = ngx.shared.ip_cache

    -- ── L1 CACHE (shared dict) ────────────────────────────────
    if cache then
        local val, flags = cache:get("bl:" .. ip)

        if val ~= nil then
            if val == 1 then
                ctx.security.ip_blacklisted = true
                ctx.security.block          = true
                ctx.security.risk           = 100

                table.insert(ctx.security.signals, "ip_blacklist_cache")
                ngx.log(ngx.WARN, "[BLACKLIST][CACHE] IP=", ip)

                if metric_blocked then
                    metric_blocked:inc(1, {"ip_blacklist_cache"})
                end
            end
            -- Nếu val == 0 (IP sạch), không phát tín hiệu rác, trả về luôn
            return
        end
    end

    -- ── L2 REDIS ─────────────────────────────────────────────
    -- [SỬA ĐỔI] Lấy kết nối từ helper, tự động trỏ vào db=0
    local red, err = redis_helper.get_redis(0)

    if not red then
        ngx.log(ngx.WARN, "[BLACKLIST] Redis unavailable: ", err)
        ctx.security.redis_bl_fail = true
        
        -- Nâng risk nếu đã có dấu hiệu đáng ngờ khác (Graceful degradation)
        if ctx.security.xff_private_client or ctx.security.bad_bot_scanner then
            ctx.security.risk = math_min((ctx.security.risk or 0) + 15, 100)
        else
            ctx.security.risk = math_min((ctx.security.risk or 0) + 5, 100)
        end
        return
    end

    -- [SỬA ĐỔI QUAN TRỌNG] Sử dụng Pipeline để gộp 2 lệnh Redis vào 1 round-trip
    red:init_pipeline()
    red:sismember("blacklist_ips", ip)
    red:get("blacklist:" .. ip)
    local results, pipe_err = red:commit_pipeline()

    -- Trả kết nối về Pool để tái sử dụng
    redis_helper.close(red)

    if not results or pipe_err then
        ngx.log(ngx.ERR, "[BLACKLIST] Redis pipeline error: ", pipe_err)
        ctx.security.redis_bl_error = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 10, 100)
        return
    end

    local manual_res = results[1]
    local auto_res   = results[2]

    -- [SỬA ĐỔI] Ép kiểu tostring() để đảm bảo an toàn với mọi giá trị lưu trên Redis
    local is_blacklisted = (manual_res == 1) 
                        or (auto_res and auto_res ~= ngx.null and tostring(auto_res) == "1")

    if is_blacklisted then
        ngx.log(ngx.WARN, "[BLACKLIST] IP=", ip)

        -- Lưu cache với số 1 (blacklisted) kèm prefix bl:
        if cache then
            cache:set("bl:" .. ip, 1, CACHE_TTL_POSITIVE)
        end

        ctx.security.ip_blacklisted = true
        ctx.security.block          = true
        ctx.security.risk           = 100

        table.insert(ctx.security.signals, "ip_blacklist")

        if metric_blocked then
            metric_blocked:inc(1, {"ip_blacklist"})
        end

        return
    end

    -- ── NEGATIVE CACHE ───────────────────────────────────────
    -- [FIX HIỆU NĂNG CHÍ MẠNG]: Cache IP sạch (số 0) vô điều kiện trong 30s.
    -- Xóa bỏ điều kiện risk < 20 để tránh việc hacker lợi dụng request rác 
    -- ép Nginx phải liên tục query xuống Redis (Bypass L1 Cache).
    if cache then
        cache:set("bl:" .. ip, 0, CACHE_TTL_NEGATIVE)
    end

    -- Đã xóa table.insert(ctx.security.signals, "ip_clean") để giảm nhiễu log
end

return _M