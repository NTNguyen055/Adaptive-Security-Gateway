local _M = {}
local ngx      = ngx
local math_min = math.min

-- FIX 6: Chuẩn hóa độ dài log User-Agent ở một hằng số duy nhất để code nhất quán
local MAX_UA_LOG = 120

-- =============================================================================
-- UA LISTS — mở rộng đầy đủ hơn
-- =============================================================================

-- FIX 5: Bổ sung các công cụ scan phổ biến và các bot trinh sát (Reconnaissance)
local SCANNERS = {
    -- Web scanners
    "sqlmap", "nikto", "nmap", "zgrab", "masscan",
    "nuclei", "dirbuster", "gobuster", "dirb", "ffuf",
    "wfuzz", "feroxbuster",
    -- Vuln scanners
    "acunetix", "nessus", "openvas", "qualys", "rapid7",
    "burpsuite", "burp suite", "owasp zap", "zaproxy", "appscan",
    -- Password/brute
    "hydra", "medusa", "patator", "thc-hydra",
    -- Crawlers/scrapers tấn công
    "wpscan", "joomscan", "droopescan",
    -- Advanced Tools / Recon
    "metasploit", "havij", "w3af", "skipfish", "arachni", "vega",
    "shodan", "censys", "binaryedge",
    -- Generic
    "scanner", "exploit", "attack", "inject",
}

local HEADLESS = {
    "headlesschrome", "headless chrome",
    "phantomjs", "slimerjs",
    "selenium", "webdriver",
    "puppeteer", "playwright",
    "cypress",
    "zombie.js", "mechanize",
}

local DEV_TOOLS = {
    "curl/", "wget/",
    "python-requests", "python-urllib",
    "go-http-client", "java/", "okhttp",
    "axios/", "node-fetch", "got/",
    "postmanruntime", "insomnia",
    "httpie", "httpx",
    "libwww-perl", "lwp-trivial",
}

local WHITELIST = {
    "googlebot", "bingbot", "slurp",           
    "duckduckbot", "baiduspider", "yandexbot",
    "facebookexternalhit", "twitterbot",       
    "linkedinbot", "whatsapp", "telegrambot",
    "applebot", "pingdom", "uptimerobot",      
    "healthchecker",                           
}

-- =============================================================================
-- HELPERS
-- =============================================================================
-- Hàm tìm kiếm literal string siêu nhanh (plain=true)
local function contains_any(s, patterns)
    for i = 1, #patterns do
        if s:find(patterns[i], 1, true) then
            return patterns[i]   
        end
    end
    return nil
end

-- =============================================================================
-- MAIN
-- =============================================================================
function _M.run(ctx)
    local ip = (ctx.security and ctx.security.client_ip)
               or ngx.var.realip_remote_addr
               or ngx.var.remote_addr

    local ua = ngx.var.http_user_agent

    ctx.security         = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    -- ── EMPTY UA ─────────────────────────────────────────────
    if not ua or ua == "" then
        ctx.security.empty_ua = true

        local base = 20
        if ctx.security.rate_limit_hard then
            base = math_min(base + 15, 100)
        end
        if ctx.security.waf_sqli or ctx.security.waf_xss then
            base = math_min(base + 20, 100)
        end

        ctx.security.risk = math_min((ctx.security.risk or 0) + base, 100)
        table.insert(ctx.security.signals, "empty_ua")

        ngx.log(ngx.WARN, "[BAD_BOT] Empty UA ip=", ip)
        return
    end

    local ua_lower = ua:lower()

    -- ── L1 CACHE (FIX 7: Tối ưu CPU, không quét lại UA đã phân loại) ──────
    -- [FIX KIẾN TRÚC]: Tách riêng ua_cache để không giành RAM với ip_cache của Blacklist
    local cache = ngx.shared.ua_cache 
    local cache_key = "ua:" .. ngx.md5(ua_lower)

    if cache then
        local cached_res = cache:get(cache_key)
        if cached_res then
            if cached_res == "whitelist" then
                ctx.security.ua_whitelisted = true
                return
            elseif cached_res == "scanner" then
                ctx.security.bad_bot_scanner = true
                ctx.security.block           = true
                ctx.security.risk            = 100
                table.insert(ctx.security.signals, "bad_bot_scanner_cached")
                return
            elseif cached_res == "headless" then
                ctx.security.bad_bot_headless = true
                ctx.security.risk = math_min((ctx.security.risk or 0) + 60, 100)
                table.insert(ctx.security.signals, "bad_bot_headless_cached")
                return
            elseif cached_res == "dev_tool" then
                ctx.security.dev_tool = true
                ctx.security.risk = math_min((ctx.security.risk or 0) + 20, 100)
                table.insert(ctx.security.signals, "dev_tool_cached")
                return
            elseif cached_res == "normal" then
                ctx.security.ua_normal = true
                return
            elseif cached_res == "unknown" then
                ctx.security.ua_unknown = true
                ctx.security.risk = math_min((ctx.security.risk or 0) + 5, 100)
                return
            end
        end
    end

    -- ── WHITELIST ─────────────────────────────────────────────
    if contains_any(ua_lower, WHITELIST) then
        ctx.security.ua_whitelisted = true
        -- Tắt hoàn toàn log INFO cho Whitelist để giữ sạch file error.log
        -- (Ngăn chặn spam log do bot thay đổi version/timestamp liên tục gây cache miss)
        -- ngx.log(ngx.INFO, "[BAD_BOT] Whitelisted ua=", ua:sub(1, MAX_UA_LOG), " ip=", ip)
        if cache then cache:set(cache_key, "whitelist", 3600) end
        return
    end

    -- ── SCANNER — hard block ngay ─────────────────────────────
    local matched_scanner = contains_any(ua_lower, SCANNERS)
    if matched_scanner then
        ctx.security.bad_bot_scanner = true
        ctx.security.block           = true
        ctx.security.risk            = 100

        table.insert(ctx.security.signals, "bad_bot_scanner:" .. matched_scanner)
        ngx.log(ngx.WARN, "[BAD_BOT] Scanner ip=", ip, " matched=", matched_scanner, " ua=", ua:sub(1, MAX_UA_LOG))
        
        if cache then cache:set(cache_key, "scanner", 3600) end
        if metric_blocked then metric_blocked:inc(1, {"bad_bot_scanner"}) end
        return
    end

    -- ── HEADLESS BROWSER ─────────────────────────────────────
    local matched_headless = contains_any(ua_lower, HEADLESS)
    if matched_headless then
        ctx.security.bad_bot_headless = true
        -- FIX 4: Tăng Risk lên 60 thay vì 40. Headless 99% là tool cào dữ liệu (Scraping)
        ctx.security.risk = math_min((ctx.security.risk or 0) + 60, 100)

        table.insert(ctx.security.signals, "bad_bot_headless:" .. matched_headless)
        ngx.log(ngx.WARN, "[BAD_BOT] Headless ip=", ip, " matched=", matched_headless, " ua=", ua:sub(1, MAX_UA_LOG))
        
        if cache then cache:set(cache_key, "headless", 3600) end
        return
    end

    -- ── DEV TOOLS ─────────────────────────────────────────────
    -- FIX 3: Đưa DEV_TOOLS lên TRƯỚC Mozilla. 
    -- Chặn các kịch bản fake UA kiểu "Mozilla/5.0 python-requests/2.28"
    local matched_dev = contains_any(ua_lower, DEV_TOOLS)
    if matched_dev then
        ctx.security.dev_tool = true

        local base = 10
        if ctx.security.rate_limit_hard then
            base = math_min(base + 10, 100)
        end

        ctx.security.risk = math_min((ctx.security.risk or 0) + base, 100)
        table.insert(ctx.security.signals, "dev_tool:" .. matched_dev)

        ngx.log(ngx.INFO, "[BAD_BOT] DevTool ip=", ip, " matched=", matched_dev, " ua=", ua:sub(1, MAX_UA_LOG))
        
        if cache then cache:set(cache_key, "dev_tool", 3600) end
        return
    end

    -- ── SAFE MOZILLA — browser thực sự ───────────────────────
    -- Kiểm tra sau scanner/headless/dev_tool
    if ua:find("Mozilla", 1, true) or ua:find("Opera", 1, true) then
        ctx.security.ua_normal = true
        if cache then cache:set(cache_key, "normal", 3600) end
        return
    end

    -- ── UNKNOWN UA ────────────────────────────────────────────
    ctx.security.ua_unknown = true
    ctx.security.risk = math_min((ctx.security.risk or 0) + 5, 100)
    table.insert(ctx.security.signals, "ua_unknown")

    ngx.log(ngx.INFO, "[BAD_BOT] Unknown UA ip=", ip, " ua=", ua:sub(1, MAX_UA_LOG))
    if cache then cache:set(cache_key, "unknown", 3600) end
end

return _M