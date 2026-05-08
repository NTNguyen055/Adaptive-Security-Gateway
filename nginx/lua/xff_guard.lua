local _M = {}
local ngx = ngx
local math_min = math.min

-- Gọi thư viện tiện ích để dùng chung các hàm kiểm tra IP
local utils = require "utils" 

-- =========================================================================
-- PARSER (Dùng để phân tích rủi ro, không dùng để xác định IP)
-- =========================================================================
local function parse_xff(xff_str)
    local ips = {}
    if not xff_str or xff_str == "" then return ips end
    for ip in xff_str:gmatch("[^,]+") do
        ip = ip:match("^%s*(.-)%s*$")
        if ip and ip ~= "" then table.insert(ips, ip) end
    end
    return ips
end

-- =========================================================================
-- MAIN
-- =========================================================================
function _M.run(ctx)
    ctx.security = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    -- [VÁ LỖ HỔNG CHÍ MẠNG]
    -- Tuyệt đối tin tưởng ngx.var.remote_addr vì Nginx (real_ip_module) 
    -- đã bóc tách XFF dựa trên Trust Zone (set_real_ip_from) trong nginx.conf
    local client_ip = ngx.var.remote_addr
    
    ctx.security.client_ip = client_ip
    ctx.security.remote_addr = client_ip

    -- Luôn đảm bảo Django nhận được IP thực đã được Gateway xác thực
    ngx.req.set_header("X-Real-IP", client_ip)

    -- =====================================================================
    -- THREAT INTELLIGENCE: Quét X-Forwarded-For để tìm dấu hiệu Hacker
    -- =====================================================================
    local xff = ngx.var.http_x_forwarded_for
    if xff then
        local ips = parse_xff(xff)

        -- 1. HARD BLOCK: XFF Chain Abuse (Bắn phá qua quá nhiều proxy ẩn danh)
        if #ips > 10 then
            ctx.security.xff_chain_abuse = true
            ctx.security.block = true
            ctx.security.risk = math_min((ctx.security.risk or 0) + 100, 100)
            table.insert(ctx.security.signals, "xff_chain_abuse")
            ngx.log(ngx.WARN, "[XFF] Chain abuse detected. Length: ", #ips)
            return
        end

        local valid_ips = {}
        local has_malformed = false

        -- Lọc danh sách IP hợp lệ thông qua utils
        for _, ip in ipairs(ips) do
            if utils.is_valid_ip(ip) then
                table.insert(valid_ips, ip)
            else
                has_malformed = true
            end
        end

        -- 2. TÍN HIỆU: Malformed XFF (Cố tình chèn ký tự lạ/mã độc vào header)
        if has_malformed then
            ctx.security.xff_malformed = true
            ctx.security.risk = math_min((ctx.security.risk or 0) + 30, 100)
            table.insert(ctx.security.signals, "xff_malformed")
        end

        -- 3. SANITIZE HEADERS: Xóa rác, chỉ đẩy mảng IP sạch xuống Django
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
    -- Tăng Risk Score lên 40 cho IP thực nếu nó thuộc dải nội bộ 
    -- (Chặn hành vi cố tình giả mạo mạng LAN để bypass hệ thống)
    if utils.is_private_ip(client_ip) then
        ctx.security.xff_private_client = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 40, 100)
        table.insert(ctx.security.signals, "xff_private_client")
    end
end

return _M