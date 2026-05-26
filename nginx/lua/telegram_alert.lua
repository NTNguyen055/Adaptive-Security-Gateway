-- =============================================================================
-- File: nginx/lua/telegram_alert.lua
-- Chức năng: Gửi cảnh báo Telegram bất đồng bộ cho các module bảo mật.
-- =============================================================================

local _M = {}
local ngx = ngx
local TELEGRAM_ALERT_TTL = 600

local function get_telegram_config()
    local token = os.getenv("TELEGRAM_BOT_TOKEN")
    local chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if token and token ~= "" and chat_id and chat_id ~= "" then
        return token, chat_id
    end
    return nil, nil
end

local function telegram_notify_timer(premature, bot_token, chat_id, text)
    if premature then
        return
    end

    local http = require "resty.http"
    local httpc = http.new()
    httpc:set_timeout(2000)

    local res, err = httpc:request_uri("https://api.telegram.org", {
        method = "POST",
        path = "/bot" .. bot_token .. "/sendMessage",
        body = ngx.encode_args({
            chat_id = chat_id,
            text = text,
            disable_web_page_preview = "true",
        }),
        headers = {
            ["Content-Type"] = "application/x-www-form-urlencoded",
        },
        ssl_verify = true,
    })

    if not res then
        ngx.log(ngx.ERR, "[TELEGRAM] request failed: ", err)
        return
    end

    if res.status ~= 200 then
        ngx.log(ngx.ERR, "[TELEGRAM] unexpected status: ", res.status, " body=", res.body or "")
    end
end

local function format_alert(opts)
    return table.concat({
        "🚨 Security Alert",
        "Time: " .. os.date("%Y-%m-%d %H:%M:%S"),
        "IP blocked: " .. (opts.ip or "unknown"),
        "Attack type: " .. (opts.attack_type or "unknown"),
        "Penalty score: " .. (opts.score and tostring(opts.score) or "n/a"),
        "Reason: " .. (opts.reason or "block threshold reached"),
        "Details: " .. (opts.details or "-"),
    }, "\n")
end

function _M.send(opts)
    if not opts or not opts.ip or not opts.attack_type then
        return
    end

    local bot_token, chat_id = get_telegram_config()
    if not bot_token then
        return
    end

    local cache_key = "tg_alert:" .. opts.ip .. ":" .. opts.attack_type
    if ngx.shared.ip_cache then
        if ngx.shared.ip_cache:get(cache_key) then
            return
        end
        ngx.shared.ip_cache:set(cache_key, 1, TELEGRAM_ALERT_TTL)
    end

    local text = format_alert(opts)
    local ok, err = ngx.timer.at(0, telegram_notify_timer, bot_token, chat_id, text)
    if not ok then
        ngx.log(ngx.ERR, "[TELEGRAM] timer create failed: ", err)
    end
end

return _M
