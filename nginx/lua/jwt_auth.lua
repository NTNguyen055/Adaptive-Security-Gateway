local _M = {}

local ngx      = ngx
local re_find  = ngx.re.find
local re_match = ngx.re.match
local math_min = math.min

-- [FIX NHẤT QUÁN CODEBASE]: Nạp thư viện SHA256 đã có sẵn trong vendor
local resty_sha256 = require "resty.sha256"
local str          = require "resty.string"

local function get_libs()
    return require "resty.jwt"
end

local function get_secret()
    local s = os.getenv("JWT_SECRET_KEY")
    if not s or s == "" then return nil end
    return s
end

local PUBLIC_PATHS = {
    ["/"]                = true,
    ["/login"]           = true,
    ["/login/"]          = true,
    ["/doLogin"]         = true,
    ["/doLogin/"]        = true,
    ["/logout/"]         = true,  
    ["/logout"]          = true,  
    ["/health/"]         = true,
    ["/health"]          = true,
    ["/favicon.ico"]     = true,
    ["/doctor/signup/"]  = true,  
    ["/userappointment/"] = true,         
    ["/User_SearchAppointment/"] = true,  
}

-- =============================================================================
-- HÀM NHẬN DIỆN GIAO DIỆN WEB
-- =============================================================================
-- Đã dọn dẹp 'logout' ra khỏi regex vì nó đã được match chính xác (Exact match) ở PUBLIC_PATHS
local WEB_PREFIXES_PATTERN = [[^/(?:static|media|admin|doctor|doctors|user|users|patient|patients|manage|search|view|update|profile|password|base)(?:/|$)]]

local function is_web_route(uri)
    if not uri then return false end
    return re_find(uri, WEB_PREFIXES_PATTERN, "ijo") ~= nil
end

local MAX_REPLAY_TTL = 3600  -- 1 giờ
local INVALID_TTL    = 60    -- Giảm thời gian cache Token lỗi xuống 60s để tiết kiệm RAM

-- =============================================================================
-- MAIN
-- =============================================================================
function _M.run(ctx)
    local JWT_SECRET = get_secret()
    if not JWT_SECRET then return end

    local uri = ngx.var.uri
    
    -- Bỏ qua kiểm tra JWT đối với các endpoint Public (như /login) 
    -- hoặc các route phục vụ giao diện Web (nơi dùng Cookie/Session thay vì Bearer Token).
    if PUBLIC_PATHS[uri] or is_web_route(uri) then
        ctx.security = ctx.security or {}
        ctx.security.jwt_public_path = true
        return
    end

    local ip = (ctx.security and ctx.security.client_ip)
               or ngx.var.realip_remote_addr
               or ngx.var.remote_addr

    local auth_header   = ngx.var.http_authorization
    local cookie_header = ngx.var.http_cookie

    ctx.security         = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    -- ── MISSING JWT ───────────────────────────────────────────
    if not auth_header then
        -- Tương thích với Session Cookie của Django
        -- Cơ chế Hybrid Auth: Nếu API không nhận được JWT, nhưng lại thấy có 
        -- Cookie sessionid (của web framework như Django/Laravel), hệ thống sẽ nhân nhượng cho đi tiếp.
        if cookie_header and re_find(cookie_header, [[sessionid=]], "jo") then
            ctx.security.jwt_missing = true
            ctx.security.using_session = true
            -- Ghi log INFO để tiện truy vết audit các luồng dùng Session
            ngx.log(ngx.INFO, "[JWT] Session fallback ip=", ip, " uri=", uri)
            return
        end

        ctx.security.jwt_missing = true
        ctx.security.block       = true

        local base = 80
        if ctx.security.rate_limit_hard  then base = math_min(base + 10, 100) end
        if ctx.security.waf_sqli or ctx.security.waf_xss then
            base = math_min(base + 15, 100)
        end

        ctx.security.risk = math_min((ctx.security.risk or 0) + base, 100)
        table.insert(ctx.security.signals, "jwt_missing")

        ngx.log(ngx.WARN, "[JWT] Missing ip=", ip, " uri=", uri)
        return
    end

    -- ── FORMAT CHECK ─────────────────────────────────────────
    -- Kiểm tra định dạng nhanh bằng Regex. Chặn đứng các payload rác 
    -- trước khi đưa vào hàm thư viện JWT phân tích (giúp tiết kiệm CPU).
    local m = re_match(
        auth_header,
        [[^Bearer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)$]],
        "jo"
    )

    if not m then
        ctx.security.jwt_malformed = true
        ctx.security.block         = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 80, 100)
        table.insert(ctx.security.signals, "jwt_malformed")
        ngx.log(ngx.WARN, "[JWT] Malformed header ip=", ip)
        return
    end

    local token   = m[1]
    local jwt_lib = get_libs()
    
    -- [FIX NHẤT QUÁN CODEBASE]: Sử dụng SHA-256 thay cho MD5 để chuẩn hóa bảo mật
    -- Băm (Hash) Token thành một chuỗi ngắn cố định. Tránh việc dùng toàn bộ 
    -- chuỗi Token dài làm Key lưu vào Cache gây lãng phí bộ nhớ (RAM).
    local sha256 = resty_sha256:new()
    sha256:update(token)
    local digest = sha256:final()
    local token_hash = str.to_hex(digest)
    
    local cache      = ngx.shared.jwt_cache

    -- ── L1 CACHE HIT ─────────────────────────────────────────
    -- CORE HIỆU NĂNG: Việc giải mã và xác thực chữ ký số (Crypto Verify) cực kỳ tốn CPU.
    -- Bằng cách lưu kết quả xác thực (số 1 là hợp lệ, 2 là lỗi) vào L1 Cache, hệ thống sẽ bỏ qua toàn bộ
    -- phép toán mã hóa ở các request tiếp theo của cùng Token đó, giúp tốc độ tăng vọt.
    if cache then
        local cached_val = cache:get(token_hash)
        if cached_val == 1 then
            ctx.security.jwt_valid      = true
            ctx.security.jwt_from_cache = true

            local uid_key = "jwt_uid:" .. token_hash
            local uid = cache:get(uid_key)
            if uid then
                ngx.req.set_header("X-User-ID", tostring(uid))
            end
            return
        end
        if cached_val == 2 then
            ctx.security.jwt_invalid = true
            ctx.security.block       = true
            ctx.security.risk        = math_min((ctx.security.risk or 0) + 80, 100)
            table.insert(ctx.security.signals, "jwt_blocked_cache")
            return
        end
    end

    -- ── LOAD JWT STRUCTURE ───────────────────────────────────
    local jwt_obj = jwt_lib:load_jwt(token)

    if not jwt_obj or not jwt_obj.valid then
        ctx.security.jwt_malformed = true
        ctx.security.block         = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 80, 100)
        table.insert(ctx.security.signals, "jwt_malformed")
        if cache then cache:set(token_hash, 2, INVALID_TTL) end
        return
    end

    -- ── ALG CHECK ────────────────────────────────────────────
    -- BẢO MẬT CORE: Ngăn chặn "Algorithm Confusion Attack". 
    -- Hacker có thể đổi header `alg` thành "none" (bỏ qua ký) hoặc "RS256" (dùng Public Key làm Secret). 
    -- Ép cứng kiểm tra phải là `HS256` để triệt tiêu toàn bộ rủi ro này.
    if not jwt_obj.header or jwt_obj.header.alg ~= "HS256" then
        ctx.security.jwt_alg_attack = true
        ctx.security.block          = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 80, 100)
        table.insert(ctx.security.signals, "jwt_alg_attack")
        ngx.log(ngx.WARN, "[JWT] Alg attack ip=", ip, " alg=", tostring(jwt_obj.header and jwt_obj.header.alg))
        if cache then cache:set(token_hash, 2, INVALID_TTL) end
        return
    end

    -- ── VERIFY SIGNATURE ─────────────────────────────────────
    -- Hàm verify lõi: Dùng Secret Key của hệ thống để băm lại Payload và đối chiếu.
    -- Nếu chữ ký không khớp -> Dữ liệu đã bị hacker sửa đổi giữa đường.
    jwt_obj = jwt_lib:verify(JWT_SECRET, token)

    if not jwt_obj or not jwt_obj.verified then
        ctx.security.jwt_invalid = true
        ctx.security.block       = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 80, 100)
        table.insert(ctx.security.signals, "jwt_invalid")
        ngx.log(ngx.WARN, "[JWT] Invalid signature ip=", ip, " reason=", tostring(jwt_obj and jwt_obj.reason))
        if cache then cache:set(token_hash, 2, INVALID_TTL) end
        return
    end

    -- ── PAYLOAD VALIDATION ───────────────────────────────────
    local payload = jwt_obj.payload
    local now     = ngx.time()

    if not payload or type(payload.user_id) ~= "number" then
        ctx.security.jwt_payload_invalid = true
        ctx.security.block               = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 80, 100)
        table.insert(ctx.security.signals, "jwt_payload_invalid")
        return
    end

    if not payload.exp then
        ctx.security.jwt_no_exp = true
        ctx.security.block      = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 80, 100)
        table.insert(ctx.security.signals, "jwt_no_exp")
        return
    end

    -- ── EXPIRY CHECK ─────────────────────────────────────────
    local ttl = payload.exp - now
    if ttl <= 0 then
        ctx.security.jwt_expired = true
        ctx.security.block       = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 80, 100)
        table.insert(ctx.security.signals, "jwt_expired")
        ngx.log(ngx.WARN, "[JWT] Expired ip=", ip, " expired_ago=", math.abs(ttl), "s")
        return
    end

    -- ── NBF CHECK ────────────────────────────────────────────
    if payload.nbf and payload.nbf > now then
        ctx.security.jwt_nbf = true
        ctx.security.block   = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 80, 100)
        table.insert(ctx.security.signals, "jwt_nbf")
        return
    end

    -- ── IAT CHECK ────────────────────────────────────
    -- Bắt những token có timestamp tạo ra ở tương lai (Dấu hiệu hacker tự bịa token)
    -- Issued At (iat) là thời điểm sinh ra Token. Nếu nó lớn hơn giờ hệ thống hiện tại,
    -- nghĩa là có sự giả mạo lộ liễu (hoặc lệch giờ máy chủ nghiêm trọng).
    if payload.iat and payload.iat > now + 5 then
        ctx.security.jwt_iat_future = true
        ctx.security.block = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 80, 100)
        table.insert(ctx.security.signals, "jwt_iat_future")
    end

    -- ── REPLAY DETECTION ─────────────────────────────────────
    local replay_key = "jwt_ip:" .. token_hash
    if cache then
        -- CHỐNG ĐÁNH CẮP TOKEN (Token Theft / XSS): Mỗi token hợp lệ được gắn 
        -- chặt vào IP gọi nó lần đầu. Nếu cùng một Token hợp lệ nhưng lát sau lại phát sinh từ một IP khác lạ,
        -- có nghĩa là Token đã bị đánh cắp (hack qua XSS/MITM). Khóa cứng + đẩy Risk lên 100 (Max).
        local prev_ip = cache:get(replay_key)
        if prev_ip and prev_ip ~= ip then
            ctx.security.jwt_replay = true
            -- JWT bị đánh cắp mang từ thiết bị khác sang -> Block cứng lập tức!
            ctx.security.block      = true 
            ctx.security.risk       = 100
            table.insert(ctx.security.signals, "jwt_replay")
            ngx.log(ngx.WARN, "[JWT] Replay detected (STOLEN TOKEN!) ip=", ip, " prev_ip=", prev_ip, " user_id=", payload.user_id)
            return
        else
            cache:set(replay_key, ip, math.min(ttl, MAX_REPLAY_TTL))
        end
    end

    -- ── CACHE VALID TOKEN ────────────────────────────────────
    if cache then
        local cache_ttl = math.min(ttl, MAX_REPLAY_TTL)
        cache:set(token_hash, 1, cache_ttl)
        cache:set("jwt_uid:" .. token_hash, payload.user_id, cache_ttl)
    end

    -- ── FORWARD IDENTITY HEADERS ─────────────────────────────
    -- Backend không cần tự verify JWT nữa. Nginx đẩy luôn thông tin User xuống 
    -- qua Header HTTP. Rất tiện cho kiến trúc Microservices.
    ngx.req.set_header("X-User-ID", tostring(payload.user_id))
    
    -- Khử trùng (Sanitize) Role để chặn đứng Header Injection
    -- Xóa bỏ mọi ký tự lạ (chỉ giữ lại chữ, số, gạch ngang, gạch dưới) 
    -- khỏi trường "role" để đề phòng kỹ thuật HTTP Header Injection nhắm vào Backend.
    local role = tostring(payload.role or "user"):gsub("[^%w_%-]", "")
    ngx.req.set_header("X-User-Role", role)

    ctx.identity = {
        user_id = payload.user_id,
        role    = role,
    }

    ctx.security.jwt_valid = true
end

return _M