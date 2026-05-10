local _M = {}
local ngx = ngx
local math_min = math.min

local utils = require "utils" 

local function parse_xff(xff_str)
    local ips = {}
    if not xff_str or xff_str == "" then return ips end
    
    for ip in xff_str:gmatch("[^,]+") do
        ip = ip:match("^%s*(.-)%s*$")
        if ip and ip ~= "" then table.insert(ips, ip) end
    end
    return ips
end

function _M.run(ctx)
    ctx.security = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    -- [FIX KIẾN TRÚC - CHUẨN HÓA REAL-IP MODULE]
    -- Do Nginx đã dùng module real_ip (set_real_ip_from), ngx.var.remote_addr 
    -- LÚC NÀY ĐÃ LÀ IP CLIENT CUỐI CÙNG được bóc tách an toàn.
    -- Còn IP kết nối TCP thô (Raw TCP IP) thực sự là ngx.var.realip_remote_addr.
    
    local client_ip  = ngx.var.remote_addr         -- IP User đã được Nginx xác thực
    local raw_tcp_ip = ngx.var.realip_remote_addr  -- IP Vật lý (Proxy/Docker/ALB/Hacker)
    
    -- Gắn IP đã xác thực vào Context để các module sau (bad_bot, risk) sử dụng
    ctx.security.client_ip = client_ip
    ctx.security.remote_addr = client_ip

    -- Đóng dấu IP thật vào Header X-Real-IP để backend (Django) sử dụng
    ngx.req.set_header("X-Real-IP", client_ip)

    -- =====================================================================
    -- THREAT INTELLIGENCE: Phân tích Header X-Forwarded-For
    -- =====================================================================
    local xff = ngx.var.http_x_forwarded_for
    if xff then
        local ips = parse_xff(xff)

        -- 1. HARD BLOCK: Chống tấn công tràn bộ nhớ (Chain Abuse)
        if #ips > 10 then
            ctx.security.xff_chain_abuse = true
            ctx.security.block = true
            ctx.security.risk = math_min((ctx.security.risk or 0) + 100, 100)
            
            table.insert(ctx.security.signals, "xff_chain_abuse")
            
            -- Ghi log thông minh: Báo cáo cả Client IP và Raw TCP IP
            ngx.log(ngx.WARN, "[XFF] Chain abuse! Client IP: ", client_ip, " (Raw TCP: ", raw_tcp_ip, ") - Chain Length: ", #ips)
            
            return
        end

        local valid_ips = {}
        local has_malformed = false

        for _, ip in ipairs(ips) do
            if utils.is_valid_ip(ip) then
                table.insert(valid_ips, ip)
            else
                has_malformed = true
            end
        end

        -- 2. TÍN HIỆU RỦI RO: Malformed XFF
        if has_malformed then
            ctx.security.xff_malformed = true
            ctx.security.risk = math_min((ctx.security.risk or 0) + 30, 100)
            table.insert(ctx.security.signals, "xff_malformed")
        end

        -- 3. SANITIZE HEADERS
        if #valid_ips > 0 then
            local sanitized_xff = table.concat(valid_ips, ", ")
            ngx.req.set_header("X-Forwarded-For", sanitized_xff)
        else
            ngx.req.clear_header("X-Forwarded-For")
        end
    end

    -- =====================================================================
    -- PRIVATE IP PENALTY
    -- =====================================================================
    -- Phạt Client IP nếu nó là dải Private (ngăn chặn spoofing XFF nội bộ)
    if utils.is_private_ip(client_ip) then
        ctx.security.xff_private_client = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 40, 100)
        table.insert(ctx.security.signals, "xff_private_client")
    end
end

return _M