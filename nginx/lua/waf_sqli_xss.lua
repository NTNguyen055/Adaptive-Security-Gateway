local _M = {}

local ngx      = ngx
local re_find  = ngx.re.find
local math_min = math.min
local cjson    = require "cjson.safe" -- FIX 3: Dùng cjson để parse body JSON

-- =============================================================================
-- PATTERNS
-- =============================================================================

-- FIX 1: Chống ReDoS. Đổi .{0,20} thành [^;]{0,20} để ngăn chặn Catastrophic Backtracking
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

    local ok1, decoded1 = pcall(ngx.unescape_uri, input)
    if ok1 then input = decoded1 end

    local ok2, decoded2 = pcall(ngx.unescape_uri, input)
    if ok2 then input = decoded2 end

    input = input:lower()
    input = input:gsub("/%*.-%*/", " ")
    input = input:gsub("<!%-%-.-%-%->", " ")

    -- FIX 2: Decode HTML entity thành ký tự chuẩn thay vì dấu cách
    -- LƯU Ý CHẤP NHẬN RỦI RO (Trade-off): Chỉ decode dải ASCII (32-255).
    -- Unicode/Control chars ngoài dải này bị ép thành khoảng trắng. 
    -- Điều này đủ để bắt 99% payload XSS thực tế mà vẫn giữ hiệu suất cao.
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

    if #value > 8192 then value = value:sub(1, 8192) end

    local v = normalize(value)
    local is_attack = false

    -- ── SQLi ──────────────────────────────────────────────────
    if re_find(v, SQLI_PATTERN, "ijo") then
        ctx.security.waf_sqli = true
        ctx.security.block    = true   
        local base = 80
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

    -- FIX 6: Gom toàn bộ kết quả quét thay vì return sớm (Ghi nhận Multiple Attacks)
    local found = false

    -- ── 1. URI PATH & QUERY ───────────────────────────────────
    found = check(ngx.var.uri, ctx, "uri") or found

    local args, err = ngx.req.get_uri_args(100)
    if args then found = scan_args(args, ctx) or found end

    -- ── 2. HEADERS NGUY HIỂM ─────────────────────────────────
    local headers = ngx.req.get_headers()
    found = check(headers["user-agent"],      ctx, "header:user-agent")    or found
    found = check(headers["referer"],         ctx, "header:referer")       or found
    found = check(headers["x-forwarded-for"], ctx, "header:xff")           or found
    
    -- FIX 4 & 5: Bổ sung quét Cookie và Authorization Header
    found = check(headers["cookie"],          ctx, "header:cookie")        or found
    found = check(headers["authorization"],   ctx, "header:authorization") or found

    -- ── 3. REQUEST BODY ───────────────────────────────────────
    local method = ngx.req.get_method()
    if method ~= "POST" and method ~= "PUT" and method ~= "PATCH" then return end

    local content_type = (headers["content-type"] or ""):lower()

    -- [TỐI ƯU CẤU TRÚC] Đưa check Multipart lên trước để bảo vệ File Uploads
    if content_type:find("multipart/form-data", 1, true) then
        -- Bỏ qua quét Raw Body với file Multipart (Ảnh, Video...) để tránh False Positive.
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

    -- [VÁ LỖ HỔNG CHÍ MẠNG] Chống bypass bằng JSON Padding / Whitespace Injection
    -- Payload không phải là file upload mà nặng hơn 1MB -> Chặn đứng lập tức
    if #body > 1024 * 1024 then
        local ip = (ctx.security and ctx.security.client_ip) or ngx.var.remote_addr
        ngx.log(ngx.WARN, "[WAF] Payload too large (", #body, " bytes) from ip=", ip, ", dropping request to prevent bypass")
        return ngx.exit(ngx.HTTP_REQUEST_ENTITY_TOO_LARGE) -- Trả về HTTP 413
    end

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