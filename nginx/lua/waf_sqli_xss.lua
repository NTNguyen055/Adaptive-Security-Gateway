local _M = {}

local ngx      = ngx
local re_find  = ngx.re.find
local math_min = math.min
local cjson    = require "cjson.safe" -- FIX 3: Dùng cjson để parse body JSON

-- =============================================================================
-- PATTERNS
-- =============================================================================

-- Các mẫu nhận diện SQL Injection. Việc dùng `[^;]` thay vì `.`
-- giúp Engine không bị sập CPU khi hacker cố tình gửi các chuỗi truy vấn siêu dài để khai thác ReDoS.
local SQLI_PATTERN = table.concat({
    [[\bunion\b[^;]{0,20}\bselect\b]],
    [[\bselect\b[^;]{0,30}\bfrom\b]],
    [[\b(?:insert|delete|drop|truncate|update)\b[^;]{0,20}\b(?:into|from|table|set)\b]],
    [[\bor\b\s+['"]?1['"]?\s*=\s*['"]?1]],    
    [[\band\b\s+['"]?1['"]?\s*=\s*['"]?1]],   
    [[--\s|#\s|/\*]],                          
    [[\bsleep\s*\(]],                          
    [[\bbenchmark\s*\(]],                      
    [[\bwaitfor\s+delay\b]],                   
    [[\bload_file\s*\(]],                      
    [[\binto\s+(?:outfile|dumpfile)\b]],       
    [[\bexec(?:ute)?\s*\(]],                   
    [[\bxp_cmdshell\b]],                       
    [[;\s*(?:drop|insert|delete|update)\b]],   
}, "|")

-- Các mẫu nhận diện Cross-Site Scripting (XSS). Nhắm vào thẻ <script>, iframe, 
-- các hàm Javascript (alert, location) và các Event Handler (onload, onerror).
local XSS_PATTERN = table.concat({
    [[<\s*script\b]],
    [[javascript\s*:]],
    [[vbscript\s*:]],                              
    [[on(?:error|load|click|mouseover|focus|blur|keyup|keydown|submit|change|input|resize|scroll)\s*=]], 
    [[<\s*(?:svg|img|body|input|link|meta|object|embed|iframe|frame|base)\b[^>]*?on\w+\s*=]],
    [[<\s*iframe\b]],
    [[document\s*\.\s*(?:cookie|write|location)]],
    [[window\s*\.\s*(?:location|open)]],
    [[(?:alert|confirm|prompt)\s*\(]],             
    [[&#\s*x?[0-9a-f]+\s*;]],                     
    [[\\u[0-9a-f]{4}]],                            
    [[expression\s*\(]],                           
    [[<\s*style\b[^>]*>.*?(?:expression|javascript)]],
}, "|")

-- =============================================================================
-- NORMALIZE — decode encoding layers để chống bypass
-- =============================================================================
local function normalize(input)
    if not input then return "" end

    -- Giải mã (Decode) URI 2 lần. Hacker thường dùng thủ thuật "Double Encoding"
    -- (Ví dụ: Encode dấu `<` thành `%253c`) để qua mặt WAF chỉ quét 1 lớp.
    local ok1, decoded1 = pcall(ngx.unescape_uri, input)
    if ok1 then input = decoded1 end

    local ok2, decoded2 = pcall(ngx.unescape_uri, input)
    if ok2 then input = decoded2 end

    input = input:lower()
    -- Xóa comment SQL (`/*...*/`) và comment HTML (``) chèn giữa mã độc.
    -- Ngăn chặn hacker ngắt nhỏ câu lệnh (Ví dụ: `sel/*...*/ect` -> `select`).
    input = input:gsub("/%*.-%*/", " ")
    input = input:gsub("<!%-%-.-%-%->", " ")

    -- Dịch ngược các dạng Entity như `&#60;` hoặc `&#x3c;` trở lại dấu `<`
    -- để Pattern Regex có thể bắt được.
    input = input:gsub("&#(%d+);", function(n)
        local num = tonumber(n)
        if num and num >= 32 and num <= 255 then return string.char(num) end
        return " "
    end)
    
    input = input:gsub("&#x(%x+);", function(h)
        local num = tonumber(h, 16)
        if num and num >= 32 and num <= 255 then return string.char(num) end
        return " "
    end)

    input = input:gsub("%s+", " ")
    input = input:gsub("%z", "")

    return input
end

-- =============================================================================
-- CHECK
-- =============================================================================
local function check(value, ctx, source)
    if not value or value == "" then return false end

    -- Cắt bớt độ dài chuỗi cần quét ở 8KB. Cân bằng giữa an toàn và tốc độ, 
    -- tránh vắt kiệt RAM & CPU bởi các payload rác cực lớn.
    if #value > 8192 then value = value:sub(1, 8192) end

    local v = normalize(value)
    local is_attack = false

    -- ── SQLi ──────────────────────────────────────────────────
    if re_find(v, SQLI_PATTERN, "ijo") then
        -- ACTION CORE: Gắn cờ bị chặn lập tức khi có SQLi và đẩy điểm rủi ro
        -- thẳng lên 80 (chạm ngưỡng block của Risk Engine).
        ctx.security.waf_sqli = true
        ctx.security.block    = true   
        local base = 80
        -- Combination Bonus: Tăng max 100 điểm nếu nhận diện được là Bot/Scanner
        -- thực hiện cuộc tấn công này (phối hợp với module chống Bot).
        if ctx.security.bad_bot_scanner then base = math_min(base + 20, 100) end
        ctx.security.risk = math_min((ctx.security.risk or 0) + base, 100)
        table.insert(ctx.security.signals, "waf_sqli")

        local ip = (ctx.security and ctx.security.client_ip) or ngx.var.remote_addr
        ngx.log(ngx.WARN, "[WAF][SQLi] ip=", ip, " source=", (source or "unknown"), " val=", v:sub(1, 120))
        
        if metric_blocked then metric_blocked:inc(1, {"waf_sqli"}) end
        is_attack = true
    end

    -- ── XSS ──────────────────────────────────────────────────
    if re_find(v, XSS_PATTERN, "ijo") then
        ctx.security.waf_xss = true
        ctx.security.block   = true   
        ctx.security.risk = math_min((ctx.security.risk or 0) + 80, 100)
        table.insert(ctx.security.signals, "waf_xss")

        local ip = (ctx.security and ctx.security.client_ip) or ngx.var.remote_addr
        ngx.log(ngx.WARN, "[WAF][XSS] ip=", ip, " source=", (source or "unknown"), " val=", v:sub(1, 120))
        
        if metric_blocked then metric_blocked:inc(1, {"waf_xss"}) end
        is_attack = true
    end

    return is_attack
end

-- =============================================================================
-- SCAN ARGS TABLE (Đệ quy tìm kiếm trong JSON/Array)
-- =============================================================================
local function scan_args(args, ctx)
    local found = false
    for k, v in pairs(args) do
        if type(v) == "table" then
            -- NÂNG CẤP: Đệ quy thực sự (Full Recursive) để quét sâu vào các JSON 
            -- lồng nhau (nested objects), chặn bypass kiểu {"a": {"b": "<script>"}}
            -- Rất quan trọng khi xử lý API trả JSON hiện đại. Không quét đệ quy
            -- thì hacker giấu payload ở level 2, level 3 sẽ lọt qua.
            found = scan_args(v, ctx) or found
        elseif type(v) == "string" or type(v) == "number" then
            found = check(tostring(v), ctx, "data:" .. tostring(k)) or found
        end
    end
    return found
end

-- =============================================================================
-- MAIN
-- =============================================================================
function _M.run(ctx)
    ctx.security         = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    -- Gom toàn bộ kết quả quét thay vì return sớm (Ghi nhận Multiple Attacks)
    -- Không ngắt quãng khi tìm thấy lỗ hổng đầu tiên. Tiếp tục quét 
    -- để lấy bằng chứng (signals) đầy đủ nhất gửi cho Risk Engine.
    local found = false

    -- ── 1. URI PATH & QUERY ───────────────────────────────────
    found = check(ngx.var.uri, ctx, "uri") or found

    local args, err = ngx.req.get_uri_args(100)
    if args then found = scan_args(args, ctx) or found end

    -- ── 2. HEADERS NGUY HIỂM ─────────────────────────────────
    -- Quét các vùng mà hacker thường lợi dụng: User-Agent bẩn, 
    -- Referer giả mạo, hoặc IP giả trong X-Forwarded-For.
    local headers = ngx.req.get_headers()
    found = check(headers["user-agent"],      ctx, "header:user-agent")    or found
    found = check(headers["referer"],         ctx, "header:referer")       or found
    found = check(headers["x-forwarded-for"], ctx, "header:xff")           or found
    
    -- Bổ sung quét Cookie và Authorization Header
    found = check(headers["cookie"],          ctx, "header:cookie")        or found
    found = check(headers["authorization"],   ctx, "header:authorization") or found

    -- ── 3. REQUEST BODY ───────────────────────────────────────
    local method = ngx.req.get_method()
    if method ~= "POST" and method ~= "PUT" and method ~= "PATCH" then return end

    local content_type = (headers["content-type"] or ""):lower()

    -- Đưa check Multipart lên trước để bảo vệ File Uploads
    if content_type:find("multipart/form-data", 1, true) then
        -- Bỏ qua quét Raw Body với file Multipart (Ảnh, Video...) để tránh False Positive.
        -- Luồng tối ưu hóa quan trọng: Không được đem Data ảnh, Video đưa qua Regex WAF.
        -- Tránh việc mã nhị phân vô tình trùng lặp chuỗi "select" hay "script" khiến request bị chặn nhầm.
        ngx.log(ngx.INFO, "[WAF] Skipped raw body scan for multipart data to prevent false positive")
        return
    end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()

    if not body then
        local file = ngx.req.get_body_file()
        if file then
            local f = io.open(file, "r")
            -- Đọc thử 1MB + 1 byte. Nếu file vượt quá mốc này, nó sẽ bị tóm ở chốt chặn bên dưới.
            if f then body = f:read(1024 * 1024 + 1); f:close() end
        end
    end

    if not body then return end

    -- Chống bypass bằng JSON Padding / Whitespace Injection
    -- Payload không phải là file upload mà nặng hơn 1MB -> Chặn đứng lập tức
    -- Bypass "bơm phồng": Kẻ tấn công tạo ra Body JSON với 2MB toàn ký tự trắng,
    -- ép WAF cạn bộ nhớ hoặc bỏ qua quét do quá lớn. Code này xử lý cứng tình trạng đó bằng cách ngắt kết nối.
    if #body > 1024 * 1024 then
        local ip = (ctx.security and ctx.security.client_ip) or ngx.var.remote_addr
        ngx.log(ngx.WARN, "[WAF] Payload too large (", #body, " bytes) from ip=", ip, ", dropping request to prevent bypass")
        return ngx.exit(ngx.HTTP_REQUEST_ENTITY_TOO_LARGE) -- Trả về HTTP 413
    end

    -- CORE: Phân giải (Parse) Body dựa theo loại Content-Type.
    if content_type:find("application/json", 1, true) then
        -- Parse cấu trúc JSON để quét chính xác từng trường (Tránh JSON escape bypass)
        local data = cjson.decode(body)
        if type(data) == "table" then
            scan_args(data, ctx)
        else
            check(body, ctx, "body:json_raw")
        end
    elseif content_type:find("application/x-www-form-urlencoded", 1, true) then
        local post_args, _ = ngx.req.get_post_args(100)
        if post_args then scan_args(post_args, ctx) else check(body, ctx, "body:form") end
    else
        check(body, ctx, "body:raw")
    end
end

return _M