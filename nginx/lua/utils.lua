-- =============================================================================
-- File: nginx/lua/utils.lua
-- Chức năng: Chứa các hàm tiện ích dùng chung cho toàn bộ module Security
-- =============================================================================

local _M = {}

-- ── Kiểm tra IPv4 hợp lệ ──────────────────────────────────────────────
function _M.is_valid_ipv4(ip)
    if not ip or type(ip) ~= "string" then return false end
    local chunks = {ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")}
    if #chunks == 4 then
        for _, v in ipairs(chunks) do
            if tonumber(v) > 255 then return false end
        end
        return true
    end
    return false
end

-- ── Kiểm tra IPv6 hợp lệ (Bao phủ Edge Cases) ─────────────────────────
function _M.is_valid_ipv6(ip)
    if not ip or #ip < 2 or #ip > 45 then return false end
    
    -- Loại bỏ dấu ngoặc vuông nếu có (Ví dụ: [::1])
    ip = ip:match("^%[(.+)%]$") or ip
    
    -- [FIX THEO REVIEW]: Bắt nhanh trường hợp all-zeros shorthand
    if ip == "::" then return true end

    -- [FIX THEO REVIEW]: Xử lý IPv4-mapped IPv6 (Ví dụ: ::ffff:192.168.1.1)
    local ipv4_part = ip:match(":(%d+%.%d+%.%d+%.%d+)$")
    if ipv4_part then
        -- Nếu phần đuôi không phải IPv4 hợp lệ -> Sai
        if not _M.is_valid_ipv4(ipv4_part) then return false end
        -- Cắt phần IPv4 đi, chỉ giữ lại phần prefix IPv6 (Ví dụ: "::ffff:") để check tiếp
        ip = ip:sub(1, -(#ipv4_part + 1))
    end

    local _, colons = ip:gsub(":", "")
    
    -- Phải có từ 2 đến 7 dấu hai chấm
    if colons < 2 or colons > 7 then return false end
    
    -- Chặn 3 dấu hai chấm liên tiếp (chuỗi rác :::)
    if ip:find(":::", 1, true) then return false end
    
    -- Không được chứa ký tự lạ (Lúc này dấu '.' của IPv4 đã bị cắt ở trên)
    return not ip:match("[^0-9a-fA-F:]")
end

-- ── Kiểm tra IP hợp lệ (Gom chung IPv4 và IPv6) ───────────────────────
function _M.is_valid_ip(ip)
    return _M.is_valid_ipv4(ip) or _M.is_valid_ipv6(ip)
end

-- ── Kiểm tra IP nội bộ (Private) / Mạng ảo ────────────────────────────
function _M.is_private_ip(ip)
    -- Tinh chỉnh nhỏ: Check nil ngay từ đầu cho nhất quán style
    if not ip or not _M.is_valid_ipv4(ip) then return false end

    -- Loopback và Link-local
    if ip:match("^127%.") then return true end
    if ip:match("^169%.254%.") then return true end

    -- RFC-1918 (Mạng LAN phổ thông)
    if ip:match("^10%.") then return true end
    if ip:match("^192%.168%.") then return true end

    -- Dải 0.0.0.0/8
    if ip:match("^0%.") then return true end

    -- Dải 172.16.0.0/12 (Docker và AWS VPC thường dùng dải này)
    local b = ip:match("^172%.(%d+)%.")
    if b then
        local n = tonumber(b)
        if n >= 16 and n <= 31 then return true end
    end

    -- Carrier-grade NAT (AWS Internal Traffic 100.64.0.0/10)
    local cgnat = ip:match("^100%.(%d+)%.")
    if cgnat then
        local n = tonumber(cgnat)
        if n >= 64 and n <= 127 then return true end
    end

    return false
end

return _M