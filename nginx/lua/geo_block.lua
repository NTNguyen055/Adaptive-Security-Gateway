local _M = {}
local math_min = math.min
local utils = require "utils"
local geo = require "resty.maxminddb"

-- =============================================================================
-- CONFIG
-- =============================================================================

-- Danh sách White-list: Các quốc gia được phép truy cập bình thường (Bypass block).
-- [FIX] Đọc từ biến môi trường GEO_ALLOWED_COUNTRIES (dạng "VN,US,SG,JP")
-- thay vì hardcode trong code. Cho phép thay đổi không cần build lại image.
-- Fallback về danh sách mặc định nếu biến không được set.
local function build_allowed_countries()
    local raw = os.getenv("GEO_ALLOWED_COUNTRIES") or ""
    local t = {}
    if raw ~= "" then
        for code in raw:gmatch("[^,]+") do
            local c = code:match("^%s*(.-)%s*$"):upper()
            if #c == 2 then t[c] = true end
        end
    end
    -- Fallback mặc định nếu env không set hoặc rỗng
    if not next(t) then
        t = { ["VN"] = true, ["US"] = true, ["SG"] = true, ["JP"] = true }
    end
    return t
end
local ALLOWED_COUNTRIES = build_allowed_countries()

-- LEVEL 4: GEO multiplier (quan trọng)
-- Hệ số nhân rủi ro dựa theo quốc gia. Các nước có tỷ lệ tấn công/spam cao (CN, RU, KP)
-- sẽ có hệ số nhân (multiplier) cao hơn, làm điểm rủi ro (risk score) tăng vọt nhanh chóng.
local GEO_MULTIPLIER = {
    VN = 1.0,
    US = 1.1,
    SG = 1.05,
    JP = 1.0,

    CN = 1.4,
    RU = 1.5,
    KP = 1.6,

    UNKNOWN = 1.3
}

-- Risk matrix (LEVEL 3)
-- Điểm rủi ro cộng dồn (Additive Risk) cho từng loại hành vi độc hại phát hiện được.
local GEO_RISK_MATRIX = {
    base_foreign = 25,

    bad_bot_scanner = 10,
    rate_limit_hard = 15,
    empty_ua = 10,

    xff_spoof = 20,
    xff_malformed = 15,

    brute_force_attack = 25,
    jwt_replay = 20
}

-- =============================================================================
-- MAIN
-- =============================================================================
function _M.run(ctx)

    -- CORE: Xác định IP thực của Client. Ưu tiên lấy từ biến ctx.security đã được
    -- module khác xử lý (ví dụ: bóc tách từ Cloudflare/Proxy), nếu không có mới dùng IP gốc của Nginx.
    local ip = (ctx.security and ctx.security.client_ip)
        or ngx.var.realip_remote_addr
        or ngx.var.remote_addr

    ctx.security = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    -- Private IP skip geo
    -- Bỏ qua tra cứu GeoIP với IP nội bộ (LAN/Localhost) để tránh lãng phí tài nguyên và lỗi.
    if not ip or utils.is_private_ip(ip) then
        ctx.security.geo_private = true
        table.insert(ctx.security.signals, "geo_private")
        return
    end

    -- Lookup geo
    -- CORE: Truy vấn MaxMind DB để tìm mã quốc gia từ IP.
    local res, err = geo.lookup(ip)

    if not res then
        ngx.log(ngx.ERR, "[GEO] lookup failed ip=", ip, " err=", err or "unknown")
        ctx.security.geo_lookup_fail = true
        return
    end

    local country = res.country and res.country.iso_code
    if not country then
        ctx.security.geo_unknown = true
        country = "UNKNOWN"
    end

    ctx.security.geo_country = country

    -- Allowed countries → bypass block
    -- CORE: Nếu IP thuộc White-list (VN, US, SG, JP), kết thúc module tại đây.
    -- Khách hợp lệ sẽ không bị dính logic Block và Risk Scoring bên dưới.
    if ALLOWED_COUNTRIES[country] then
        ctx.security.geo_allowed = true
        return
    end

    -- =========================
    -- BLOCK TRIGGER
    -- =========================
    -- CORE ACTION: Bật cờ (flag) chặn truy cập (block=true) vì đây là IP 
    -- đến từ quốc gia KHÔNG nằm trong danh sách ALLOWED_COUNTRIES.
    ctx.security.geo_blocked = true
    ctx.security.block = true

    -- =========================
    -- RISK SCORING (LEVEL 3 + 4 + 5)
    -- =========================

    -- Khởi tạo điểm rủi ro nền (base risk) dành cho IP ngoại (không thuộc allow list).
    local risk_add = GEO_RISK_MATRIX.base_foreign

    -- Tích lũy điểm rủi ro: Nếu Request này đã bị gắn cờ lỗi từ các module trước đó
    -- (ví dụ: là bot xấu, vượt quá rate limit, giả mạo IP...), thì cộng thêm điểm phạt tương ứng.
    if ctx.security.bad_bot_scanner then
        risk_add = risk_add + GEO_RISK_MATRIX.bad_bot_scanner
    end

    if ctx.security.rate_limit_hard then
        risk_add = risk_add + GEO_RISK_MATRIX.rate_limit_hard
    end

    if ctx.security.empty_ua then
        risk_add = risk_add + GEO_RISK_MATRIX.empty_ua
    end

    if ctx.security.xff_spoof then
        risk_add = risk_add + GEO_RISK_MATRIX.xff_spoof
    end

    if ctx.security.xff_malformed then
        risk_add = risk_add + GEO_RISK_MATRIX.xff_malformed
    end

    if ctx.security.brute_force_attack then
        risk_add = risk_add + GEO_RISK_MATRIX.brute_force_attack
    end

    if ctx.security.jwt_replay then
        risk_add = risk_add + GEO_RISK_MATRIX.jwt_replay
    end

    -- =========================
    -- LEVEL 4: MULTIPLICATIVE RISK (IMPORTANT FIX)
    -- =========================
    -- Lấy hệ số nhân cơ bản theo quốc gia (vd: RU = 1.5).
    local multiplier = GEO_MULTIPLIER[country] or GEO_MULTIPLIER.UNKNOWN

    -- combo attack amplification
    -- CORE: Tính năng khuếch đại rủi ro (Amplification). 
    -- Nếu IP vừa thuộc quốc gia bị cấm, VÀ vừa có hành vi rà quét (bot scanner) -> Tăng mạnh hệ số nhân.
    -- Giúp trừng phạt cực nặng các Botnet đến từ nước ngoài.
    if ctx.security.bad_bot_scanner and not ALLOWED_COUNTRIES[country] then
        multiplier = multiplier + 0.2
    end

    if ctx.security.rate_limit_hard then
        multiplier = multiplier + 0.1
    end

    if ctx.security.xff_spoof then
        multiplier = multiplier + 0.2
    end

    -- Nhân tổng điểm tích lũy với hệ số khuếch đại.
    risk_add = risk_add * multiplier

    -- clamp
    -- Cắt trần (Clamp): Đảm bảo điểm rủi ro tăng thêm không vượt quá ngưỡng tối đa là 100.
    risk_add = math_min(risk_add, 100)

    -- apply
    -- CORE: Cộng điểm rủi ro vừa tính toán được vào tổng điểm rủi ro chung của toàn bộ Request,
    -- (tối đa toàn cục cũng là 100). Biến ctx.security.risk này sẽ được các module sau dùng để quyết định chặn/captcha.
    ctx.security.risk = math_min((ctx.security.risk or 0) + risk_add, 100)

    table.insert(ctx.security.signals, "geo_block:" .. country)

    ngx.log(
        ngx.WARN,
        "[GEO] BLOCK country=",
        country,
        " ip=",
        ip,
        " risk_add=",
        risk_add,
        " multiplier=",
        multiplier
    )
end

return _M