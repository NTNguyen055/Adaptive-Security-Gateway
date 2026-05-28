local _M = {}

-- Tạo alias local để truy cập nhanh hơn thay vì gọi ngx.xxx nhiều lần.
local ngx      = ngx

-- Alias hàm math.min để tối ưu hiệu năng.
local math_min = math.min

-- Giới hạn độ dài User-Agent khi ghi log.
-- Tránh log quá dài gây phình file error.log.
local MAX_UA_LOG = 120

-- =============================================================================
-- UA LISTS — DANH SÁCH NHẬN DIỆN USER-AGENT
-- =============================================================================

-- Danh sách các công cụ tấn công, quét lỗ hổng,
-- reconnaissance và brute force phổ biến.
-- Nếu UA chứa các chuỗi này → Block ngay.
local SCANNERS = {
    -- Web scanners
    "sqlmap", "nikto", "nmap", "zgrab", "masscan",
    "nuclei", "dirbuster", "gobuster", "dirb", "ffuf",
    "wfuzz", "feroxbuster",

    -- Vulnerability scanners
    "acunetix", "nessus", "openvas", "qualys", "rapid7",
    "burpsuite", "burp suite", "owasp zap", "zaproxy", "appscan",

    -- Password brute force tools
    "hydra", "medusa", "patator", "thc-hydra",

    -- CMS scanners
    "wpscan", "joomscan", "droopescan",

    -- Advanced Recon tools
    "metasploit", "havij", "w3af", "skipfish", "arachni", "vega",
    "shodan", "censys", "binaryedge",

    -- Generic keywords
    "scanner", "exploit", "attack", "inject",
}

-- Các Headless Browser thường dùng để crawl dữ liệu,
-- automation hoặc bot scraping.
local HEADLESS = {
    "headlesschrome", "headless chrome",
    "phantomjs", "slimerjs",
    "selenium", "webdriver",
    "puppeteer", "playwright",
    "cypress",
    "zombie.js", "mechanize",
}

-- Các công cụ lập trình hoặc gửi request tự động.
-- Không block nhưng tăng risk score.
local DEV_TOOLS = {
    "curl/", "wget/",
    "python-requests", "python-urllib",
    "go-http-client", "java/", "okhttp",
    "axios/", "node-fetch", "got/",
    "postmanruntime", "insomnia",
    "httpie", "httpx",
    "libwww-perl", "lwp-trivial",
}

-- Danh sách bot hợp lệ.
-- Cho phép bỏ qua kiểm tra nhằm tránh false positive.
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

-- Hàm kiểm tra chuỗi có chứa bất kỳ pattern nào không.
-- Sử dụng plain=true nên nhanh hơn regex.
--
-- Ví dụ:
-- contains_any("sqlmap/1.8", SCANNERS)
-- => "sqlmap"
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

    -- Lấy IP thật của client.
    -- Ưu tiên:
    -- 1. security context
    -- 2. real_ip module
    -- 3. remote_addr
    local ip = (ctx.security and ctx.security.client_ip)
               or ngx.var.realip_remote_addr
               or ngx.var.remote_addr

    -- Lấy User-Agent từ HTTP Header.
    local ua = ngx.var.http_user_agent

    -- Khởi tạo security context nếu chưa tồn tại.
    ctx.security         = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    -- =========================================================================
    -- EMPTY USER AGENT
    -- =========================================================================
    -- Nhiều bot hoặc công cụ scan không gửi User-Agent.
    -- Đây là dấu hiệu bất thường nên cộng điểm rủi ro.
    if not ua or ua == "" then

        ctx.security.empty_ua = true

        local base = 20

        -- Nếu đồng thời bị Rate Limit Hard
        -- => mức độ nghi ngờ tăng.
        if ctx.security.rate_limit_hard then
            base = math_min(base + 15, 100)
        end

        -- Nếu đồng thời có SQLi hoặc XSS
        -- => tăng mạnh risk score.
        if ctx.security.waf_sqli or ctx.security.waf_xss then
            base = math_min(base + 20, 100)
        end

        ctx.security.risk =
            math_min((ctx.security.risk or 0) + base, 100)

        table.insert(ctx.security.signals, "empty_ua")

        ngx.log(
            ngx.WARN,
            "[BAD_BOT] Empty UA ip=",
            ip
        )

        return
    end

    -- Chuyển toàn bộ UA về chữ thường
    -- để tìm kiếm không phân biệt hoa thường.
    local ua_lower = ua:lower()

    -- =========================================================================
    -- L1 CACHE
    -- =========================================================================
    --
    -- Ý tưởng:
    -- User-Agent giống nhau thường xuất hiện rất nhiều lần.
    --
    -- Thay vì:
    -- Scanner List -> Headless -> Dev Tool -> Mozilla
    -- quét lại liên tục,
    --
    -- cache kết quả phân loại vào Shared Dictionary.
    --
    -- Lần sau chỉ cần đọc cache O(1).
    --
    local cache = ngx.shared.ua_cache

    -- Tạo key cache bằng MD5 của UA.
    local cache_key = "ua:" .. ngx.md5(ua_lower)

    if cache then

        local cached_res = cache:get(cache_key)

        if cached_res then

            -- ===============================================================
            -- WHITELIST CACHE
            -- ===============================================================
            if cached_res == "whitelist" then

                ctx.security.ua_whitelisted = true
                return

            -- ===============================================================
            -- SCANNER CACHE
            -- ===============================================================
            elseif cached_res:find("^scanner:", 1) then

                local scanner_name =
                    cached_res:match("^scanner:(.+)$")
                    or "unknown"

                ctx.security.bad_bot_scanner = true
                ctx.security.block           = true
                ctx.security.risk            = 100

                table.insert(
                    ctx.security.signals,
                    "bad_bot_scanner:" .. scanner_name
                )

                ngx.log(
                    ngx.WARN,
                    "[BAD_BOT] Scanner(CACHED) ip=",
                    ip,
                    " matched=",
                    scanner_name
                )

                return

            -- ===============================================================
            -- HEADLESS CACHE
            -- ===============================================================
            elseif cached_res:find("^headless:", 1) then

                local tool =
                    cached_res:match("^headless:(.+)$")
                    or "unknown"

                ctx.security.bad_bot_headless = true

                ctx.security.risk = math_min(
                    (ctx.security.risk or 0) + 60,
                    100
                )

                table.insert(
                    ctx.security.signals,
                    "bad_bot_headless:" .. tool
                )

                return

            -- ===============================================================
            -- DEV TOOL CACHE
            -- ===============================================================
            elseif cached_res:find("^dev_tool:", 1) then

                local tool =
                    cached_res:match("^dev_tool:(.+)$")
                    or "unknown"

                ctx.security.dev_tool = true

                ctx.security.risk = math_min(
                    (ctx.security.risk or 0) + 10,
                    100
                )

                table.insert(
                    ctx.security.signals,
                    "dev_tool:" .. tool
                )

                return

            -- ===============================================================
            -- NORMAL BROWSER CACHE
            -- ===============================================================
            elseif cached_res == "normal" then

                ctx.security.ua_normal = true
                return

            -- ===============================================================
            -- UNKNOWN CACHE
            -- ===============================================================
            elseif cached_res == "unknown" then

                ctx.security.ua_unknown = true

                ctx.security.risk = math_min(
                    (ctx.security.risk or 0) + 5,
                    100
                )

                table.insert(
                    ctx.security.signals,
                    "ua_unknown:cached"
                )

                return
            end
        end
    end

    -- =========================================================================
    -- WHITELIST
    -- =========================================================================
    -- Bot hợp lệ:
    -- Googlebot, Bingbot, UptimeRobot,...
    if contains_any(ua_lower, WHITELIST) then

        ctx.security.ua_whitelisted = true

        -- Không ghi INFO log để tránh spam log.
        -- ngx.log(...)

        if cache then
            cache:set(cache_key, "whitelist", 3600)
        end

        return
    end

    -- =========================================================================
    -- SCANNER DETECTION
    -- =========================================================================
    -- Nếu phát hiện công cụ scan:
    -- SQLMap, Nuclei, BurpSuite,...
    -- => Block ngay lập tức.
    local matched_scanner = contains_any(
        ua_lower,
        SCANNERS
    )

    if matched_scanner then

        ctx.security.bad_bot_scanner = true

        -- Yêu cầu gateway chặn request.
        ctx.security.block = true

        -- Risk tuyệt đối.
        ctx.security.risk = 100

        table.insert(
            ctx.security.signals,
            "bad_bot_scanner:" .. matched_scanner
        )

        ngx.log(
            ngx.WARN,
            "[BAD_BOT] Scanner ip=",
            ip,
            " matched=",
            matched_scanner,
            " ua=",
            ua:sub(1, MAX_UA_LOG)
        )

        if cache then
            cache:set(
                cache_key,
                "scanner:" .. matched_scanner,
                21600
            )
        end

        if metric_blocked then
            metric_blocked:inc(
                1,
                {"bad_bot_scanner"}
            )
        end

        return
    end

    -- =========================================================================
    -- HEADLESS DETECTION
    -- =========================================================================
    -- Selenium, Puppeteer, Playwright...
    -- Không block trực tiếp nhưng tăng risk rất cao.
    local matched_headless =
        contains_any(ua_lower, HEADLESS)

    if matched_headless then

        ctx.security.bad_bot_headless = true

        ctx.security.risk =
            math_min(
                (ctx.security.risk or 0) + 60,
                100
            )

        table.insert(
            ctx.security.signals,
            "bad_bot_headless:" .. matched_headless
        )

        ngx.log(
            ngx.WARN,
            "[BAD_BOT] Headless ip=",
            ip,
            " matched=",
            matched_headless,
            " ua=",
            ua:sub(1, MAX_UA_LOG)
        )

        if cache then
            cache:set(
                cache_key,
                "headless:" .. matched_headless,
                3600
            )
        end

        if metric_blocked then
            metric_blocked:inc(
                1,
                {"bad_bot_headless"}
            )
        end

        return
    end

    -- =========================================================================
    -- DEV TOOL DETECTION
    -- =========================================================================
    --
    -- Đặt trước Mozilla để phát hiện:
    -- Mozilla/5.0 python-requests/2.31
    --
    local matched_dev =
        contains_any(ua_lower, DEV_TOOLS)

    if matched_dev then

        ctx.security.dev_tool = true

        local base = 10

        if ctx.security.rate_limit_hard then
            base = math_min(base + 10, 100)
        end

        ctx.security.risk =
            math_min(
                (ctx.security.risk or 0) + base,
                100
            )

        table.insert(
            ctx.security.signals,
            "dev_tool:" .. matched_dev
        )

        ngx.log(
            ngx.INFO,
            "[BAD_BOT] DevTool ip=",
            ip,
            " matched=",
            matched_dev,
            " ua=",
            ua:sub(1, MAX_UA_LOG)
        )

        if cache then
            cache:set(
                cache_key,
                "dev_tool:" .. matched_dev,
                3600
            )
        end

        return
    end

    -- =========================================================================
    -- NORMAL BROWSER
    -- =========================================================================
    --
    -- Chrome, Firefox, Edge, Opera...
    --
    if ua:find("Mozilla", 1, true)
       or ua:find("Opera", 1, true)
    then

        ctx.security.ua_normal = true

        if cache then
            cache:set(
                cache_key,
                "normal",
                3600
            )
        end

        return
    end

    -- =========================================================================
    -- UNKNOWN USER-AGENT
    -- =========================================================================
    --
    -- Không khớp bất kỳ danh sách nào.
    -- Chưa đủ căn cứ block nên chỉ tăng risk nhẹ.
    --
    ctx.security.ua_unknown = true

    ctx.security.risk =
        math_min(
            (ctx.security.risk or 0) + 5,
            100
        )

    table.insert(
        ctx.security.signals,
        "ua_unknown"
    )

    ngx.log(
        ngx.INFO,
        "[BAD_BOT] Unknown UA ip=",
        ip,
        " ua=",
        ua:sub(1, MAX_UA_LOG)
    )

    if cache then
        cache:set(
            cache_key,
            "unknown",
            3600
        )
    end
end

return _M