local _M = {}
local ngx = ngx
local math_min = math.min

-- Gọi thư viện tiện ích để dùng chung các hàm kiểm tra IP (như kiểm tra IP nội bộ, IP hợp lệ)
local utils = require "utils" 

-- =========================================================================
-- HÀM PARSER: Phân tích chuỗi X-Forwarded-For (XFF)
-- Mục đích: Chỉ dùng để trích xuất mảng IP từ chuỗi nhằm phân tích rủi ro, 
-- TUYỆT ĐỐI KHÔNG dùng hàm này để gán IP thật cho người dùng.
-- =========================================================================
local function parse_xff(xff_str)
    local ips = {}
    if not xff_str or xff_str == "" then return ips end
    
    -- Tách chuỗi bằng dấu phẩy, loại bỏ khoảng trắng dư thừa ở 2 đầu
    for ip in xff_str:gmatch("[^,]+") do
        ip = ip:match("^%s*(.-)%s*$")
        if ip and ip ~= "" then table.insert(ips, ip) end
    end
    return ips
end

-- =========================================================================
-- HÀM MAIN: Luồng thực thi chính của Module XFF Guard
-- =========================================================================
function _M.run(ctx)
    -- Khởi tạo context security để truyền dữ liệu giữa các file Lua
    ctx.security = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    -- [VÁ LỖ HỔNG CHÍ MẠNG - ENTERPRISE STANDARD]
    -- Nguồn sự thật duy nhất (Single Source of Truth):
    -- Lấy IP ở tầng kết nối TCP (ngx.var.remote_addr). Đây là IP không thể bị giả mạo.
    -- Mọi hình phạt (Risk Score, Blacklist) sẽ giáng trực tiếp xuống IP này.
    local real_tcp_ip = ngx.var.remote_addr
    
    -- Gắn chặt IP thật vào Context để các module sau (bad_bot, risk_engine) sử dụng
    ctx.security.client_ip = real_tcp_ip
    ctx.security.remote_addr = real_tcp_ip

    -- Đóng dấu IP thật vào Header X-Real-IP để backend (Django) tin tưởng sử dụng
    ngx.req.set_header("X-Real-IP", real_tcp_ip)

    -- =====================================================================
    -- THREAT INTELLIGENCE: Phân tích Header X-Forwarded-For do Client gửi lên
    -- =====================================================================
    local xff = ngx.var.http_x_forwarded_for
    if xff then
        local ips = parse_xff(xff)

        -- 1. HARD BLOCK: Chống tấn công tràn bộ nhớ (Header Buffer Overflow / Chain Abuse)
        -- Nếu hacker nhồi quá 10 IP vào Header để làm treo hệ thống
        if #ips > 10 then
            ctx.security.xff_chain_abuse = true
            ctx.security.block = true
            ctx.security.risk = math_min((ctx.security.risk or 0) + 100, 100)
            
            table.insert(ctx.security.signals, "xff_chain_abuse")
            
            -- Ghi log cảnh báo kèm theo IP TCP thật của kẻ tấn công
            ngx.log(ngx.WARN, "[XFF] Chain abuse detected from REAL IP: ", real_tcp_ip, " - Chain Length: ", #ips)
            
            -- Trả về ngay lập tức, chặn request không cho đi tiếp
            return
        end

        local valid_ips = {}
        local has_malformed = false

        -- Lọc danh sách IP: Phân loại IP sạch và IP chứa mã độc/ký tự lạ
        for _, ip in ipairs(ips) do
            if utils.is_valid_ip(ip) then
                table.insert(valid_ips, ip)
            else
                has_malformed = true
            end
        end

        -- 2. TÍN HIỆU RỦI RO: Malformed XFF (Cố tình chèn mã XSS/SQLi vào Header IP)
        -- Ví dụ: X-Forwarded-For: 1.1.1.1, <script>alert(1)</script>
        if has_malformed then
            ctx.security.xff_malformed = true
            ctx.security.risk = math_min((ctx.security.risk or 0) + 30, 100) -- Phạt 30 điểm
            table.insert(ctx.security.signals, "xff_malformed")
        end

        -- 3. SANITIZE HEADERS (Làm sạch dữ liệu): 
        -- Nginx đóng vai trò là máy giặt, xóa bỏ các IP chứa mã độc và 
        -- chỉ đẩy một mảng XFF hoàn toàn sạch sẽ (Valid IP) xuống cho Django.
        if #valid_ips > 0 then
            local sanitized_xff = table.concat(valid_ips, ", ")
            ngx.req.set_header("X-Forwarded-For", sanitized_xff)
        else
            -- Nếu toàn bộ chuỗi XFF là rác, xóa sạch Header này trước khi gửi cho backend
            ngx.req.clear_header("X-Forwarded-For")
        end
    end

    -- =====================================================================
    -- PRIVATE IP PENALTY (Phạt lỗi giả mạo LAN)
    -- =====================================================================
    -- Kiểm tra IP kết nối TCP gốc. Nếu IP này thuộc dải mạng LAN riêng tư (10.x, 192.168.x, 172.16.x)
    -- Nó có thể là hacker đang giả mạo proxy nội bộ, hoặc (trong trường hợp của chúng ta) 
    -- là request đi qua mạng nội bộ của Docker Bridge.
    if utils.is_private_ip(real_tcp_ip) then
        ctx.security.xff_private_client = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 40, 100) -- Phạt 40 điểm
        table.insert(ctx.security.signals, "xff_private_client")
    end
end

return _M