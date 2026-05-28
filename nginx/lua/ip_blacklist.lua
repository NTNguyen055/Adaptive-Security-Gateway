local _M = {}
local math_min = math.min
local redis_helper = require "redis_helper" -- [THÊM MỚI] Gọi module dùng chung
-- telegram_alert: removed from here to centralize alerts in risk_engine.lua

-- Giảm thời gian cache để việc gỡ ban (unban) thủ công có tác dụng nhanh hơn
local CACHE_TTL_POSITIVE = 60 
local CACHE_TTL_NEGATIVE = 30

-- ============================================================
-- MAIN
-- ============================================================
function _M.run(ctx)
    -- Ưu tiên dùng client_ip đã normalize từ xff_guard
    -- Dùng IP thực đã được XFF Guard xử lý và bóc tách khỏi các Proxy giả mạo.
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
        -- Đọc L1 Cache (RAM của Worker Nginx). Đây là lá chắn đầu tiên.
        -- Cực kỳ nhanh, giúp Nginx chịu tải hàng chục nghìn RPS từ các IP đã bị block
        -- mà không cần kết nối tới Redis.
        local val, flags = cache:get("bl:" .. ip)

        if val ~= nil then
            if val == 1 then
                -- Revalidate với Redis để việc xóa blacklist bằng tay có tác dụng ngay.
                -- Khi IP bị cấm, ta thỉnh thoảng kiểm tra lại với Redis. 
                -- Nếu Admin chủ động vào Redis xóa IP này để ân xá (unban), hệ thống sẽ cập nhật ngay
                -- thay vì bắt người dùng chờ hết thời gian CACHE_TTL_POSITIVE (1 phút).
                local red, err = redis_helper.get_redis(0)
                if red then
                    red:init_pipeline()
                    red:sismember("blacklist_ips", ip)
                    red:get("blacklist:" .. ip)
                    local results, pipe_err = red:commit_pipeline()
                    redis_helper.close(red)

                    if results and not pipe_err then
                        local manual_res = results[1]
                        local auto_res   = results[2]
                        local is_key_blacklisted = auto_res and auto_res ~= ngx.null and tostring(auto_res) == "1"
                        local is_set_blacklisted = manual_res == 1

                        if is_key_blacklisted then
                            ctx.security.ip_blacklisted = true
                            ctx.security.block          = true
                            ctx.security.risk           = 100

                            table.insert(ctx.security.signals, "ip_blacklist_cache")
                            ngx.log(ngx.WARN, "[BLACKLIST][CACHE] IP=", ip)
                            ngx.log(ngx.NOTICE, "[TELEGRAM SUPPRESSED] ip_blacklist_cache alert suppressed for ip=", ip)

                            if metric_blocked then
                                metric_blocked:inc(1, {"ip_blacklist_cache"})
                            end
                            return
                        end

                        if is_set_blacklisted and not is_key_blacklisted then
                            ngx.log(ngx.WARN, "[BLACKLIST] Stale blacklist membership detected for IP=", ip, " during cache revalidation")
                            local cleanup_red, cleanup_err = redis_helper.get_redis(0)
                            if cleanup_red then
                                cleanup_red:srem("blacklist_ips", ip)
                                redis_helper.close(cleanup_red)
                            else
                                ngx.log(ngx.ERR, "[BLACKLIST] Cleanup redis unavailable: ", cleanup_err)
                            end
                            cache:set("bl:" .. ip, 0, CACHE_TTL_NEGATIVE)
                            return
                        end

                        cache:set("bl:" .. ip, 0, CACHE_TTL_NEGATIVE)
                        return
                    else
                        ngx.log(ngx.ERR, "[BLACKLIST] Redis revalidation error: ", pipe_err)
                        ctx.security.ip_blacklisted = true
                        ctx.security.block          = true
                        ctx.security.risk           = 100

                        table.insert(ctx.security.signals, "ip_blacklist_cache")
                        if metric_blocked then
                            metric_blocked:inc(1, {"ip_blacklist_cache"})
                        end
                        return
                    end
                else
                    -- Fail-closed: Nếu đứt kết nối Redis khi đang revalidate, 
                    -- cứ tiếp tục Block (giữ an toàn làm trọng).
                    ctx.security.ip_blacklisted = true
                    ctx.security.block          = true
                    ctx.security.risk           = 100

                    table.insert(ctx.security.signals, "ip_blacklist_cache")
                    if metric_blocked then
                        metric_blocked:inc(1, {"ip_blacklist_cache"})
                    end
                    return
                end
            end
            -- Nếu val == 0 (IP sạch), không phát tín hiệu rác, trả về luôn
            return
        end
    end

    -- ── L2 REDIS ─────────────────────────────────────────────
    -- Lấy kết nối từ helper, tự động trỏ vào db=0
    -- Nếu không có trong L1 Cache (cache miss), phải truy vấn Redis (L2 Cache).
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

    -- Sử dụng Pipeline để gộp 2 lệnh Redis vào 1 round-trip
    -- TỐI ƯU I/O: Kiểm tra cả 2 nơi (Set thủ công của Admin và Key TTL tự động của Risk Engine) 
    -- trong cùng 1 cục mạng, giảm một nửa thời gian chờ (latency).
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
    local is_key_blacklisted = auto_res and auto_res ~= ngx.null and tostring(auto_res) == "1"
    local is_set_blacklisted = manual_res == 1

    if is_key_blacklisted then
        ngx.log(ngx.WARN, "[BLACKLIST] IP=", ip)

        -- Lưu cache với số 1 (blacklisted) kèm prefix bl:
        if cache then
            cache:set("bl:" .. ip, 1, CACHE_TTL_POSITIVE)
        end

        -- ACTION CORE: Gắn cờ Block, đẩy Risk lên Max và bắn signal 
        -- để ngắt toàn bộ các công đoạn xử lý Security đằng sau.
        ctx.security.ip_blacklisted = true
        ctx.security.block          = true
        ctx.security.risk           = 100

        table.insert(ctx.security.signals, "ip_blacklist")
        ngx.log(ngx.NOTICE, "[TELEGRAM SUPPRESSED] ip_blacklist alert suppressed for ip=", ip)

        if metric_blocked then
            metric_blocked:inc(1, {"ip_blacklist"})
        end

        return
    end

    if is_set_blacklisted and not is_key_blacklisted then
        ngx.log(ngx.WARN, "[BLACKLIST] Stale blacklist membership detected for IP=", ip, " during full redis check")
        local cleanup_red, cleanup_err = redis_helper.get_redis(0)
        if cleanup_red then
            cleanup_red:srem("blacklist_ips", ip)
            redis_helper.close(cleanup_red)
        else
            ngx.log(ngx.ERR, "[BLACKLIST] Cleanup redis unavailable: ", cleanup_err)
        end

        if cache then
            cache:set("bl:" .. ip, 0, CACHE_TTL_NEGATIVE)
        end
        return
    end

    -- ── NEGATIVE CACHE ───────────────────────────────────────
    -- Cache IP sạch (số 0) vô điều kiện trong 30s.
    -- Xóa bỏ điều kiện risk < 20 để tránh việc hacker lợi dụng request rác 
    -- ép Nginx phải liên tục query xuống Redis (Bypass L1 Cache).
    -- CỰC KỲ QUAN TRỌNG: "Cache lại cả sự thật rằng IP này KHÔNG bị block".
    -- Nếu không có dòng này, với mỗi request hợp lệ, Nginx đều phải gọi Redis, 
    -- làm tê liệt DB khi hệ thống nhận hàng nghìn user truy cập cùng lúc.
    if cache then
        cache:set("bl:" .. ip, 0, CACHE_TTL_NEGATIVE)
    end

    -- Đã xóa table.insert(ctx.security.signals, "ip_clean") để giảm nhiễu log
end

return _M