-- Blacklist enforcement regression (manual, authorized, legacy).
-- Run: luajit nginx/tests/test_ip_blacklist.lua nginx/lua/ip_blacklist.lua
local source = arg[1] or 'nginx/lua/ip_blacklist.lua'
local ip = '192.0.2.42'
local state
local null = {}
local cache = {items = {}, ttls = {}}
local records = {}

package.loaded['cjson.safe'] = {
    decode = function(raw) return records[raw] end,
}

_G.ngx = {
    WARN = 4, ERR = 3, INFO = 6, NOTICE = 5, null = null,
    var = {remote_addr = ip, realip_remote_addr = ip},
    log = function(...) end,
    shared = {ip_cache = cache},
}

function cache:get(key) return self.items[key] end
function cache:set(key, value, ttl)
    self.items[key] = value
    self.ttls[key] = ttl
    return true
end

local red = {}
function red:init_pipeline() state.pipe = {} end
function red:sismember(key, value)
    state.pipe[#state.pipe + 1] = {'sismember', key, value}
end
function red:get(key)
    state.pipe[#state.pipe + 1] = {'get', key}
end
function red:pttl(key)
    state.pipe[#state.pipe + 1] = {'pttl', key}
end
function red:commit_pipeline()
    if state.fail_pipeline then return nil, 'timeout' end
    if state.invalid_replies then return state.invalid_replies end
    assert(#state.pipe == 4, 'expected 4 Redis commands')
    assert(state.pipe[1][2] == 'blacklist_ips')
    assert(state.pipe[2][2] == 'blacklist:' .. ip)
    assert(state.pipe[3][2] == 'ban:v2:ip:' .. ip)
    assert(state.pipe[4][2] == 'ban:v2:ip:' .. ip)
    return {
        state.manual and 1 or 0,
        state.legacy and '1' or null,
        state.authorized or null,
        state.pttl or -2,
    }
end
function red:close() state.closed = state.closed + 1 end
function red:set() error('Enforcement must not issue a ban') end
function red:sadd() error('Enforcement must not mutate manual bans') end
function red:del() error('Enforcement must not delete bans') end

package.loaded.redis_helper = {
    get_redis = function(db)
        assert(db == 0)
        state.connects = state.connects + 1
        if state.unavailable then return nil, 'unavailable' end
        return red
    end,
    close = function(conn)
        assert(conn == red)
        state.pooled = state.pooled + 1
    end,
}

local module = assert(loadfile(source))()
local passed, failed = 0, 0
local function reset()
    state = {manual = false, legacy = false, authorized = nil, pttl = nil,
        unavailable = false, fail_pipeline = false, invalid_replies = nil,
        connects = 0, pooled = 0, closed = 0, pipe = {}}
    cache.items, cache.ttls = {}, {}
    records = {}
end
local function request()
    local ctx = {security = {client_ip = ip, risk = 12, signals = {}}}
    module.run(ctx)
    return ctx.security
end
local function test(name, fn)
    reset()
    local ok, err = pcall(fn)
    if ok then
        passed = passed + 1
        print('PASS  ' .. name)
    else
        failed = failed + 1
        print('FAIL  ' .. name .. ': ' .. tostring(err))
    end
end
local function valid_record()
    records['valid-record'] = {
        schema = 1, scope = 'ip', ip = ip,
        issuer = 'security_correlator',
        reason = 'confirmed_exploit_campaign',
        incident_id = 'abcdeffedcba0123456789abcdef0001',
        issued_at = 1000, expires_at = 1060, ttl_seconds = 60,
    }
    state.authorized = 'valid-record'
    state.pttl = 55000
end

test('clean IP is allowed and cached negative', function()
    local s = request()
    assert(not s.block and s.risk == 12)
    assert(cache.items['bl:' .. ip] == 0 and cache.ttls['bl:' .. ip] == 5)
end)

test('negative cache hit skips Redis', function()
    request(); request()
    assert(state.connects == 1)
end)

test('legacy automatic TTL key still enforced during migration', function()
    state.legacy = true
    local s = request()
    assert(s.block and s.ban_origin == 'legacy')
    assert(s.signals[1] == 'ip_blacklist_auto')
end)

test('expired legacy automatic key releases request', function()
    state.legacy = true; request()
    state.legacy = false
    local s = request()
    assert(not s.block and s.risk == 12)
end)

test('manual ban is still enforced', function()
    state.manual = true
    local s = request()
    assert(s.block and s.ban_origin == 'manual')
    assert(s.signals[1] == 'ip_blacklist_manual')
end)

test('manual ban overrides legacy automatic ban', function()
    state.manual = true; state.legacy = true
    assert(request().ban_origin == 'manual')
end)

test('manual unban revalidated on positive cache', function()
    state.manual = true; request()
    state.manual = false
    assert(not request().block and state.connects == 2)
end)

test('Redis outage on cache miss is not false evidence', function()
    state.unavailable = true
    local s = request()
    assert(not s.block and s.risk == 12 and s.redis_bl_fail)
end)

test('Redis outage after confirmed ban conservatively denies', function()
    state.manual = true; request()
    state.unavailable = true
    local s = request()
    assert(s.block and s.ban_origin == 'cached_unverified')
end)

test('pipeline failure without cache does not mark clean', function()
    state.fail_pipeline = true
    local s = request()
    assert(not s.block and s.redis_bl_error)
    assert(cache.items['bl:' .. ip] == nil)
    assert(state.closed == 1 and state.pooled == 0)
end)

test('pipeline failure after ban preserves cached denial', function()
    state.manual = true; request()
    state.fail_pipeline = true
    assert(request().block)
end)

test('malformed Redis pipeline response is rejected', function()
    state.invalid_replies = {false, null, null, -2}
    local s = request()
    assert(s.redis_bl_error and not s.block)
end)

test('negative-cache TTL remains 5 seconds', function()
    request()
    state.manual = true
    assert(not request().block and cache.ttls['bl:' .. ip] == 5)
end)

test('authorized V2 ban enforced with metadata and TTL', function()
    valid_record()
    local s = request()
    assert(s.block and s.ban_origin == 'authorized_v2')
    assert(s.signals[1] == 'ip_blacklist_auto')
end)

test('authorized ban expiration releases IP', function()
    valid_record(); request()
    state.authorized, state.pttl = nil, nil
    assert(not request().block)
end)

test('manual ban takes precedence over authorized V2 ban', function()
    valid_record(); state.manual = true
    assert(request().ban_origin == 'manual')
end)

test('authorized record for different IP is not trusted', function()
    valid_record(); records['valid-record'].ip = '198.51.100.55'
    local s = request()
    assert(not s.block and s.redis_bl_error)
    assert(cache.items['bl:' .. ip] == nil)
end)

test('authorized record with no expiry does not ban', function()
    valid_record(); state.pttl = -1
    local s = request()
    assert(not s.block and s.redis_bl_error)
end)

test('authorized record beyond 300 seconds does not ban', function()
    valid_record(); state.pttl = 300001
    local s = request()
    assert(not s.block and s.redis_bl_error)
end)

test('wrong issuer in metadata does not ban', function()
    valid_record(); records['valid-record'].issuer = 'risk_engine'
    local s = request()
    assert(not s.block and s.redis_bl_error)
end)

test('unparseable metadata does not ban', function()
    state.authorized, state.pttl = 'unknown-blob', 5000
    local s = request()
    assert(not s.block and s.redis_bl_error)
end)

test('legacy ban remains effective when V2 metadata malformed', function()
    state.authorized, state.pttl = 'unknown-blob', 5000
    state.legacy = true
    local s = request()
    assert(s.block and s.ban_origin == 'legacy')
end)

print(string.format('IP Blacklist A3.4 tests: %d passed, %d failed, %d total',
    passed, failed, passed + failed))
if failed > 0 then os.exit(1) end
