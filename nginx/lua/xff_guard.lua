local _M = {}

local ngx = ngx
local math_min = math.min
local utils = require "utils"

-- ============================================================
-- CONFIG
-- ============================================================
local MAX_XFF_CHAIN = 10

-- ============================================================
-- HELPERS
-- ============================================================
local function parse_xff(xff_str)
    local ips = {}
    if not xff_str or xff_str == "" then return ips end

    for ip in xff_str:gmatch("[^,]+") do
        ip = ip:match("^%s*(.-)%s*$")
        if ip and ip ~= "" then
            table.insert(ips, ip)
        end
    end

    return ips
end

local function trim(s, n)
    return (s and #s > n) and s:sub(1, n) .. "..." or s
end

-- ============================================================
-- MAIN
-- ============================================================
function _M.run(ctx)

    ctx.security = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    ----------------------------------------------------------------
    -- REAL IP (FIXED SAFETY ORDER)
    ----------------------------------------------------------------
    local client_ip = ngx.var.remote_addr or ngx.var.realip_remote_addr
    local raw_tcp_ip = ngx.var.realip_remote_addr or ngx.var.remote_addr

    ctx.security.client_ip = client_ip
    ctx.security.remote_addr = client_ip

    ngx.req.set_header("X-Real-IP", client_ip)

    ----------------------------------------------------------------
    -- XFF ANALYSIS
    ----------------------------------------------------------------
    local xff = ngx.var.http_x_forwarded_for

    if xff and xff ~= "" then

        local ips = parse_xff(xff)

        ------------------------------------------------------------
        -- 1. CHAIN ABUSE
        ------------------------------------------------------------
        if #ips > MAX_XFF_CHAIN then

            ctx.security.xff_chain_abuse = true
            ctx.security.block = true
            ctx.security.risk = math_min((ctx.security.risk or 0) + 100, 100)

            table.insert(ctx.security.signals, "xff_chain_abuse")

            ngx.log(
                ngx.WARN,
                "[XFF] Chain abuse client_ip=",
                client_ip,
                " raw_tcp_ip=",
                raw_tcp_ip,
                " chain_length=",
                #ips,
                " xff=",
                trim(xff, 120)
            )

            return
        end

        ------------------------------------------------------------
        -- 2. VALIDATION
        ------------------------------------------------------------
        local valid_ips = {}
        local has_malformed = false
        local has_private_chain = false
        local first_ip = ips[1]

        for _, ip in ipairs(ips) do

            if utils.is_valid_ip(ip) then

                table.insert(valid_ips, ip)

                if utils.is_private_ip(ip) then
                    has_private_chain = true
                end

            else
                has_malformed = true
            end
        end

        ------------------------------------------------------------
        -- 2.1 SPOOF DETECTION (NEW FIX)
        ------------------------------------------------------------
        if first_ip and utils.is_valid_ip(first_ip) then
            if first_ip ~= client_ip and not utils.is_private_ip(first_ip) then
                ctx.security.xff_spoof = true
                ctx.security.risk = math_min((ctx.security.risk or 0) + 20, 100)
                table.insert(ctx.security.signals, "xff_spoof")

                ngx.log(
                    ngx.WARN,
                    "[XFF] Spoof detected client_ip=",
                    client_ip,
                    " first_xff=",
                    first_ip,
                    " raw_tcp_ip=",
                    raw_tcp_ip
                )
            end
        end

        ------------------------------------------------------------
        -- 3. MALFORMED XFF
        ------------------------------------------------------------
        if has_malformed then

            ctx.security.xff_malformed = true
            ctx.security.risk = math_min((ctx.security.risk or 0) + 30, 100)
            table.insert(ctx.security.signals, "xff_malformed")

            ngx.log(
                ngx.WARN,
                "[XFF] Malformed header client_ip=",
                client_ip,
                " raw_tcp_ip=",
                raw_tcp_ip,
                " xff=",
                trim(xff, 120)
            )
        end

        ------------------------------------------------------------
        -- 4. PRIVATE IP INJECTION
        ------------------------------------------------------------
        if has_private_chain then

            ctx.security.xff_private_chain = true
            ctx.security.risk = math_min((ctx.security.risk or 0) + 15, 100)

            table.insert(ctx.security.signals, "xff_private_chain")

            ngx.log(
                ngx.WARN,
                "[XFF] Private IP injection client_ip=",
                client_ip,
                " raw_tcp_ip=",
                raw_tcp_ip,
                " xff=",
                trim(xff, 120)
            )
        end

        ------------------------------------------------------------
        -- 5. SANITIZE
        ------------------------------------------------------------
        if #valid_ips > 0 then

            local sanitized_xff = table.concat(valid_ips, ", ")
            ngx.req.set_header("X-Forwarded-For", sanitized_xff)

            if sanitized_xff ~= xff then
                ngx.log(
                    ngx.INFO,
                    "[XFF] Sanitized old=",
                    trim(xff, 120),
                    " new=",
                    sanitized_xff
                )
            end

        else
            ngx.req.clear_header("X-Forwarded-For")

            ngx.log(
                ngx.WARN,
                "[XFF] Header removed client_ip=",
                client_ip,
                " raw_tcp_ip=",
                raw_tcp_ip,
                " original=",
                trim(xff, 120)
            )
        end
    end

    ----------------------------------------------------------------
    -- PRIVATE CLIENT IP
    ----------------------------------------------------------------
    if client_ip and utils.is_valid_ip(client_ip) and utils.is_private_ip(client_ip) then

        ctx.security.xff_private_client = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 15, 100)

        table.insert(ctx.security.signals, "xff_private_client")

        ngx.log(
            ngx.WARN,
            "[XFF] Private client IP detected client_ip=",
            client_ip,
            " raw_tcp_ip=",
            raw_tcp_ip
        )
    end
end

return _M