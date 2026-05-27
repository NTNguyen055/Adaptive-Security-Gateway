-- =============================================================================
-- File: nginx/lua/telegram_alert.lua
-- Chức năng:
--   Gửi cảnh báo Telegram bất đồng bộ cho Security Gateway.
--
-- Thiết kế:
--   - Gửi JSON trực tiếp.
--   - Chống spam alert bằng shared dict cache.
--   - Chạy async bằng ngx.timer.at().
-- =============================================================================

local _M = {}

local ngx   = ngx
local cjson = require("cjson.safe")

local TELEGRAM_ALERT_TTL = 600

-- =============================================================================
-- TELEGRAM CONFIG
-- =============================================================================

local function get_telegram_config()
    local token   = os.getenv("TELEGRAM_BOT_TOKEN")
    local chat_id = os.getenv("TELEGRAM_CHAT_ID")

    if token and token ~= ""
       and chat_id and chat_id ~= "" then
        return token, chat_id
    end

    return nil, nil
end

-- =============================================================================
-- FORMAT ALERT MESSAGE
-- =============================================================================

local function format_alert(opts)
    local ip          = tostring(opts.ip or "unknown")
    local attack_type = tostring(opts.attack_type or "unknown")
    local score       = tostring(opts.score or "n/a")
    local details     = tostring(opts.details or "-")

    return table.concat({
        "🛡️ SECURITY GATEWAY ALERT",
        "────────────────────────",
        "Thời gian : " .. os.date("%Y-%m-%d %H:%M:%S"),
        "IP        : " .. ip,
        "Tấn công  : " .. attack_type,
        "Điểm      : " .. score,
        "Chi tiết  : " .. details,
        "────────────────────────",
        "Trạng thái: IP đã bị BLACKLIST."
    }, "\n")
end

-- =============================================================================
-- SEND TELEGRAM
-- =============================================================================

local function telegram_notify_timer(premature, bot_token, chat_id, text)
    if premature then
        return
    end

    local http = require("resty.http")

    local httpc = http.new()
    httpc:set_timeout(3000)

    local payload, err = cjson.encode({
        chat_id = chat_id,
        text = text,
        disable_web_page_preview = true
    })

    if not payload then
        ngx.log(
            ngx.ERR,
            "[TELEGRAM] failed to encode payload: ",
            err or "unknown"
        )
        return
    end

    local res, req_err = httpc:request_uri(
        "https://api.telegram.org",
        {
            method = "POST",
            path = "/bot" .. bot_token .. "/sendMessage",
            body = payload,
            headers = {
                ["Content-Type"] = "application/json",
                ["Host"] = "api.telegram.org"
            },
            ssl_verify = false
        }
    )

    if not res then
        ngx.log(
            ngx.ERR,
            "[TELEGRAM] request failed: ",
            req_err or "unknown"
        )
        return
    end

    if res.status ~= 200 then
        ngx.log(
            ngx.ERR,
            "[TELEGRAM] unexpected status=",
            res.status,
            " body=",
            res.body or ""
        )
        return
    end

    ngx.log(
        ngx.INFO,
        "[TELEGRAM] alert sent successfully status=",
        res.status
    )
end

-- =============================================================================
-- PUBLIC API
-- =============================================================================

function _M.send(opts)
    if not opts
       or not opts.ip
       or not opts.attack_type then
        return
    end

    local bot_token, chat_id = get_telegram_config()

    if not bot_token then
        return
    end

    local cache_key =
        "tg_alert:" ..
        tostring(opts.ip) ..
        ":" ..
        tostring(opts.attack_type)

    if ngx.shared.ip_cache:get(cache_key) then
        return
    end

    ngx.shared.ip_cache:set(
        cache_key,
        true,
        TELEGRAM_ALERT_TTL
    )

    local text = format_alert(opts)

    local ok, err = ngx.timer.at(
        0,
        telegram_notify_timer,
        bot_token,
        chat_id,
        text
    )

    if not ok then
        ngx.log(
            ngx.ERR,
            "[TELEGRAM] failed to create timer: ",
            err
        )
    end
end

return _M