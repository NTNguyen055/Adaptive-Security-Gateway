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
local WEB_PREFIXES_PATTERN = [[^/(?:static|media|sys-admin-panel|admin|doctor|doctors|userbase|user|users|patient|patients|manage|search|view|update|profile|password|base)(?:/|$)]]

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
    -- Loại bỏ identity headers do client tự cung cấp.
    ngx.req.clear_header("X-User-ID")
    ngx.req.clear_header("X-User-Role")

    local uri = ngx.var.uri

    -- Public endpoints và Web routes sử dụng Django Session.
    if PUBLIC_PATHS[uri] or is_web_route(uri) then
        ctx.security = ctx.security or {}
        ctx.security.jwt_public_path = true
        return
    end

    -- Fail closed khi thiếu JWT secret trên protected routes.
    local JWT_SECRET = get_secret()

    if not JWT_SECRET then
        ctx.security = ctx.security or {}
        ctx.security.block = true
        ctx.security.jwt_config_error = true

        ngx.log(
            ngx.ERR,
            "[JWT] Missing JWT_SECRET_KEY; denying protected request"
        )

        return
    end

    local ip = (ctx.security and ctx.security.client_ip)
               or ngx.var.realip_remote_addr
               or ngx.var.remote_addr

    local auth_header = ngx.var.http_authorization

    ctx.security         = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    -- ── MISSING JWT ───────────────────────────────────────────
    if not auth_header then

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
            local uid = cache:get("jwt_uid:" .. token_hash)
            local role = cache:get("jwt_role:" .. token_hash)
            local bound_ip = cache:get("jwt_ip:" .. token_hash)

            -- Chỉ sử dụng cache khi đủ thông tin xác thực.
            -- Cache thiếu dữ liệu sẽ đi tiếp xuống bước verify JWT.
            if uid and role and bound_ip then

                -- Không cho phép cache hit bỏ qua replay detection.
                if bound_ip ~= ip then
                    ctx.security.jwt_replay = true
                    ctx.security.block = true

                    table.insert(
                        ctx.security.signals,
                        "jwt_replay"
                    )

                    ngx.log(
                        ngx.WARN,
                        "[JWT] Cached token IP mismatch ip=",
                        ip,
                        " expected_ip=",
                        bound_ip
                    )

                    return
                end

                -- Khôi phục đầy đủ identity.
                ngx.req.set_header("X-User-ID", tostring(uid))
                ngx.req.set_header("X-User-Role", role)

                ctx.identity = {
                    user_id = uid,
                    role = role,
                }

                ctx.security.jwt_valid = true
                ctx.security.jwt_from_cache = true

                return
            end
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
        return
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

    -- ── FORWARD IDENTITY HEADERS ─────────────────────────────
    -- Backend không cần tự verify JWT nữa. Nginx đẩy luôn thông tin User xuống 
    -- qua Header HTTP. Rất tiện cho kiến trúc Microservices.
    ngx.req.set_header("X-User-ID", tostring(payload.user_id))
    
    -- Khử trùng (Sanitize) Role để chặn đứng Header Injection
    -- Xóa bỏ mọi ký tự lạ (chỉ giữ lại chữ, số, gạch ngang, gạch dưới) 
    -- khỏi trường "role" để đề phòng kỹ thuật HTTP Header Injection nhắm vào Backend.
    local role = tostring(payload.role or "user"):gsub("[^%w_%-]", "")

    -- Cache đầy đủ identity sau khi JWT đã được xác minh.
    if cache then
        local cache_ttl = math.min(ttl, MAX_REPLAY_TTL)

        cache:set("jwt_uid:" .. token_hash, payload.user_id, cache_ttl)
        cache:set("jwt_role:" .. token_hash, role, cache_ttl)

        -- Ghi cờ hợp lệ sau cùng.
        cache:set(token_hash, 1, cache_ttl)
    end

    ngx.req.set_header("X-User-Role", role)

    ctx.identity = {
        user_id = payload.user_id,
        role    = role,
    }

    ctx.security.jwt_valid = true
end

return _M