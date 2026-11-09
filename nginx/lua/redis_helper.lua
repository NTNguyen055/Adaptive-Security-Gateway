-- =============================================================================
-- File: nginx/lua/redis_helper.lua
-- Chức năng: Cấp phát kết nối Redis, chọn DB và quản lý connection pool.
-- =============================================================================

local redis = require "resty.redis"
local _M = {}

function _M.get_redis(db_index)
    local red = redis:new()

    red:set_timeouts(200, 200, 500)

    local ok, err = red:connect("redis", 6379)
    if not ok then
        return nil, "connect failed: " .. tostring(err)
    end

    local db = db_index or 0
    local ok2, err2 = red:select(db)

    if not ok2 then
        -- Không để connection bị bỏ quên khi SELECT thất bại.
        red:close()
        return nil, "select db " .. tostring(db) .. " failed: " .. tostring(err2)
    end

    return red
end

function _M.close(red)
    if red then
        local ok, err = red:set_keepalive(10000, 100)

        if not ok then
            -- Nếu không đưa được connection vào pool thì đóng nó.
            red:close()
        end
    end
end

return _M
