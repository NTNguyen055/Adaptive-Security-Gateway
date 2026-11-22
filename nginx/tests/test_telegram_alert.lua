-- Isolated Lua unit tests. No network requests and no Telegram credentials leaked.
-- Place: nginx/tests/test_telegram_alert.lua
-- Run with LuaJIT in a disposable OpenResty container.
local cache = {}
local timers = {}
local schedule_error = false
local cache_error = false

local dict = {}
function dict:add(k, value, ttl)
    if cache_error then return nil, "no memory" end
    if cache[k] then return nil, "exists" end
    cache[k] = {value=value, ttl=ttl}
    return true
end
function dict:delete(k)
    cache[k] = nil
end
function dict:get(k)
    return cache[k] and cache[k].value or nil
end

_G.ngx = {
    ERR=1, WARN=2, INFO=3,
    shared={ip_cache=dict},
    log=function(...) end,
    timer={at=function(_, fn, ...)
        if schedule_error then return nil, "test timer failure" end
        timers[#timers+1] = {fn=fn, args={...}}
        return true
    end},
}
-- Avoid invoking genuine Telegram/JSON/network modules.
package.loaded['cjson.safe'] = {encode=function() return '{}' end}
package.loaded['resty.http'] = {
    new=function()
        return {set_timeout=function() end,
                request_uri=function() return {status=200,body='ok'} end}
    end,
}
local source = (arg and arg[1]) or '/tmp/lua/telegram_alert.lua'
local alert = assert(loadfile(source))()
local function fire(ip)
    alert.send({ip=ip, attack_type='Brute Force Login', details='test'})
end
-- supply no bot env? Process needs dummy env to test call; do not expose credentials.
if not (os.getenv('TELEGRAM_BOT_TOKEN') and os.getenv('TELEGRAM_CHAT_ID')) then
    error('Test requires non-secret dummy TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID environment values')
end
fire('198.51.100.10')
assert(#timers == 1, 'first alert must schedule')
fire('198.51.100.10')
assert(#timers == 1, 'duplicate alert must be suppressed')
print('PASS atomic dedup')

local key = 'tg_alert:198.51.100.10:Brute Force Login'
assert(cache[key], 'cache key should be set')
timers[1].fn(true, unpack(timers[1].args))
assert(not cache[key], 'aborted timer must release dedup key')
fire('198.51.100.10')
assert(#timers == 2, 'alert should reschedule after aborted timer')
print('PASS premature callback releases dedup')

schedule_error = true
fire('198.51.100.11')
assert(cache['tg_alert:198.51.100.11:Brute Force Login'] == nil,
       'failed schedule must not suppress future sends')
schedule_error = false
fire('198.51.100.11')
assert(#timers == 3, 'alert should schedule after timer error')
print('PASS schedule failure releases dedup')

cache_error = true
fire('198.51.100.12')
assert(#timers == 4, 'dedup cache error should not disable security alert')
cache_error = false
print('PASS cache unavailable still schedules alert')

-- Verify success path with mocked HTTP, not Telegram network.
timers[4].fn(false, unpack(timers[4].args))
print('PASS mock Telegram delivery')
print('5 tests PASS')
