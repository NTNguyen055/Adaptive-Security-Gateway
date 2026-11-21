-- Fail-closed issuance and Redis writer boundary regression.
-- Run: luajit nginx/tests/test_ip_ban_issuer.lua nginx/lua/ip_ban_issuer.lua
local source = arg[1] or 'nginx/lua/ip_ban_issuer.lua'
local lua_dir = source:match('^(.*[/\\])') or 'nginx/lua/'
package.path = lua_dir .. '?.lua;' .. package.path

local passed, failed = 0, 0
local state
local red = {}
local ip = '198.51.100.14'
local incident_id = 'abcdeffedcba0123456789abcdef0001'

_G.ngx = {
    WARN = 4,
    ERR = 3,
    log = function(...) end,
    shared = { ip_cache = {
        delete = function(_, key)
            state.cache_deleted[#state.cache_deleted + 1] = key
        end,
    } },
}

function red:eval(script, nkeys, ...)
    local args = {...}
    state.evals[#state.evals + 1] = {script = script, nkeys = nkeys, args = args}
    assert(nkeys == 1 and args[1] == 'ban:v2:ip:' .. ip)
    assert(args[2] == ip and args[3] == incident_id and args[4] == 300)
    assert(script:find("redis.call('SET', key, record, 'NX', 'EX', ttl)", 1, true))
    assert(script:find("cjson.encode", 1, true))
    assert(not script:find('blacklist_ips', 1, true))
    assert(not script:find('blacklist:', 1, true))
    if state.eval_error then return nil, 'simulated EVAL failure' end
    return state.eval_reply
end
function red:close() state.closed = state.closed + 1 end

package.loaded.redis_helper = {
    get_redis = function(db)
        assert(db == 0)
        state.connections = state.connections + 1
        if state.redis_down then return nil, 'simulated Redis outage' end
        return red
    end,
    close = function(conn)
        assert(conn == red)
        state.pooled = state.pooled + 1
    end,
}

local writer = assert(loadfile(source))()
local function verified_candidate()
    return {
        mode = 'automatic', scope = 'ip', ip = ip,
        issuer = 'security_correlator', peer_ip_verified = true,
        ttl_seconds = 900,
        evidence = {
            reason = 'confirmed_exploit_campaign',
            incident_id = incident_id,
            server_verified = true,
            independent_sources_verified = true,
            nat_assessment = 'low_collateral_verified',
            shared_ip_observed = false,
            confirmed_exploit_events = 8,
            distinct_windows = 3,
            distinct_attack_classes = 2,
            first_seen = 1000,
            last_seen = 1150,
        },
    }
end

local function reset()
    state = {
        evals = {},
        connections = 0,
        pooled = 0,
        closed = 0,
        cache_deleted = {},
        eval_reply = 1,
    }
    package.loaded.security_correlator = nil
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

local function trusted(build)
    package.loaded.security_correlator = {
        verify = function(_) return build() end,
    }
end

test('Installed shadow correlator rejects unverified incidents', function()
    local result, err = writer.issue_verified({
        approved = true,
    })

    assert(
        result == nil
            and err == 'correlation_not_verified'
    )

    assert(state.connections == 0)
    assert(#state.evals == 0)
end)

test('Correlator must expose verify function', function()
    package.loaded.security_correlator = {approved = true}
    local result, err = writer.issue_verified({approved = true})
    assert(result == nil and err == 'trusted_correlator_unavailable')
end)

test('Correlator verification crash fails closed', function()
    package.loaded.security_correlator = {
        verify = function() error('invalid evidence') end,
    }
    local result, err = writer.issue_verified({})
    assert(result == nil and err == 'correlation_not_verified')
    assert(state.connections == 0)
end)

test('Correlator malformed output fails closed', function()
    trusted(function() return 'approved' end)
    local result, err = writer.issue_verified({})
    assert(result == nil and err == 'correlation_not_verified')
end)

test('Forged approved flag cannot bypass policy', function()
    trusted(function()
        return {approved = true, mode = 'automatic', scope = 'ip',
                issuer = 'security_correlator', ip = ip,
                peer_ip_verified = true, ttl_seconds = 60}
    end)
    local result, err = writer.issue_verified({})
    assert(result == nil and err == 'ban_policy_denied:evidence_missing')
    assert(state.connections == 0)
end)

test('Raw score alone cannot issue a ban', function()
    trusted(function()
        local c = verified_candidate()
        c.evidence.reason = 'high_risk_score'
        return c
    end)
    local result, err = writer.issue_verified({risk = 100})
    assert(result == nil and err == 'ban_policy_denied:unsupported_reason')
    assert(state.connections == 0)
end)

test('Shared NAT is never authorized', function()
    trusted(function()
        local c = verified_candidate()
        c.evidence.shared_ip_observed = true
        return c
    end)
    local result, err = writer.issue_verified({})
    assert(result == nil and err == 'ban_policy_denied:shared_ip_or_unknown_collateral')
    assert(state.connections == 0)
end)

test('Verified campaign creates exactly one bounded Redis key', function()
    trusted(verified_candidate)
    local result, err = writer.issue_verified({})
    assert(err == nil and result.status == 'ISSUED')
    assert(result.ttl_seconds == 300)
    assert(#state.evals == 1 and state.pooled == 1 and state.closed == 0)
    assert(state.cache_deleted[1] == 'bl:' .. ip)
end)

test('Existing ban is not renewed or overwritten', function()
    trusted(verified_candidate)
    state.eval_reply = 0
    local result, err = writer.issue_verified({})
    assert(err == nil and result.status == 'ALREADY_ACTIVE')
    assert(#state.cache_deleted == 0 and state.pooled == 1)
end)

test('Redis connection failure never claims issuance', function()
    trusted(verified_candidate)
    state.redis_down = true
    local result, err = writer.issue_verified({})
    assert(result == nil and err:find('ban_storage_unavailable:', 1, true))
    assert(#state.evals == 0 and #state.cache_deleted == 0)
end)

test('Redis EVAL failure discards connection and fails closed', function()
    trusted(verified_candidate)
    state.eval_error = true
    local result, err = writer.issue_verified({})
    assert(result == nil and err:find('ban_storage_unconfirmed:', 1, true))
    assert(state.closed == 1 and state.pooled == 0)
    assert(#state.cache_deleted == 0)
end)

test('Malformed Redis EVAL response never claims success', function()
    trusted(verified_candidate)
    state.eval_reply = 'OK'
    local result = writer.issue_verified({})
    assert(result == nil and state.closed == 1)
end)

package.loaded.security_correlator = nil
print(string.format('IP Ban Issuer tests: %d passed, %d failed, %d total',
    passed, failed, passed + failed))
if failed > 0 then os.exit(1) end
