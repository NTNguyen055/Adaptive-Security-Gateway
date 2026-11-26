-- P0.2.4-A3 contract: pure Lua, no ngx/Redis/HTTP or credentials required.
-- Execute from the repository root: luajit nginx/tests/test_ip_ban_authorizer.lua
package.path = 'nginx/lua/?.lua;' .. package.path
local policy = assert(require('ip_ban_authorizer'))
local total = 0
local function check(name, input, approved, reason, ttl)
    local out, err = policy.authorize(input)
    assert(out, name .. ': unexpected error ' .. tostring(err))
    assert(out.approved == approved, name .. ': approved=' .. tostring(out.approved))
    assert(out.reason == reason, name .. ': reason=' .. tostring(out.reason))
    if ttl then assert(out.ttl_seconds == ttl, name .. ': ttl=' .. tostring(out.ttl_seconds)) end
    assert(out.scope == 'ip', name .. ': wrong scope')
    total = total + 1
    print('PASS ' .. name)
end
local function invalid(name, input, message)
    local out, err = policy.authorize(input)
    assert(out == nil and err == message, name .. ': err=' .. tostring(err))
    total = total + 1
    print('PASS ' .. name)
end
local function candidate()
    return {
        mode='automatic', scope='ip', ip='198.51.100.14',
        issuer='security_correlator', peer_ip_verified=true,
        ttl_seconds=900,
        evidence={
            reason='confirmed_exploit_campaign',
            incident_id='abcdeffedcba0123456789abcdef0001',
            server_verified=true, independent_sources_verified=true,
            nat_assessment='low_collateral_verified', shared_ip_observed=false,
            confirmed_exploit_events=8, distinct_windows=3,
            distinct_attack_classes=2, first_seen=1000, last_seen=1150,
        },
    }
end
local function mutate(fn)
    local c=candidate(); fn(c,c.evidence); return c
end
check('A3 repeated verified campaign gets <=300s authorization',candidate(),true,'confirmed_exploit_campaign',300)
check('A3 short TTL preserved',mutate(function(c) c.ttl_seconds=60 end),true,'confirmed_exploit_campaign',60)
check('A3 manual ban lives in existing manual workflow',mutate(function(c) c.mode='manual' end),false,'not_automatic_issuance')
check('A3 account scope cannot become IP ban',mutate(function(c) c.scope='account' end),false,'wrong_scope')
check('A3 risk engine cannot authorize bans',mutate(function(c) c.issuer='risk_engine' end),false,'untrusted_issuer')
check('A3 brute force counter cannot authorize IP bans',mutate(function(c) c.issuer='brute_force_login' end),false,'untrusted_issuer')
check('A3 Django V2 cannot authorize IP bans',mutate(function(c) c.issuer='login_accounting' end),false,'untrusted_issuer')
check('A3 XFF IP claim not verified',mutate(function(c) c.peer_ip_verified=false end),false,'unverified_ip_identity')
check('A3 injection in IP rejected',mutate(function(c) c.ip='198.51.100.1\nSET' end),false,'unverified_ip_identity')
check('A3 missing evidence rejected',mutate(function(c) c.evidence=nil end),false,'evidence_missing')
check('A3 JWT invalid alone not an exploit campaign',mutate(function(c,e) e.reason='jwt_invalid' end),false,'unsupported_reason')
check('A3 no incident reference',mutate(function(c,e) e.incident_id='' end),false,'invalid_incident_reference')
check('A3 unverified events rejected',mutate(function(c,e) e.server_verified=false end),false,'unverified_evidence')
check('A3 no independent sources rejected',mutate(function(c,e) e.independent_sources_verified=false end),false,'unverified_evidence')
check('A3 confirmed shared NAT IP rejected',mutate(function(c,e) e.shared_ip_observed=true end),false,'shared_ip_or_unknown_collateral')
check('A3 unknown NAT impact rejected',mutate(function(c,e) e.nat_assessment='unknown' end),false,'shared_ip_or_unknown_collateral')
check('A3 absent NAT statement rejected',mutate(function(c,e) e.shared_ip_observed=nil end),false,'shared_ip_or_unknown_collateral')
check('A3 one WAF match insufficient',mutate(function(c,e) e.confirmed_exploit_events=1 end),false,'insufficient_corroboration')
check('A3 two time windows insufficient',mutate(function(c,e) e.distinct_windows=2 end),false,'insufficient_corroboration')
check('A3 one class of evidence insufficient',mutate(function(c,e) e.distinct_attack_classes=1 end),false,'insufficient_corroboration')
check('A3 burst within 30s insufficient',mutate(function(c,e) e.last_seen=1030 end),false,'insufficient_corroboration')
check('A3 invalid event count rejected',mutate(function(c,e) e.confirmed_exploit_events='8' end),false,'invalid_evidence_counts')
invalid('A3 malformed top-level input',false,'invalid_candidate')
invalid('A3 invalid TTL',mutate(function(c) c.ttl_seconds=0 end),'invalid_ttl')
print(string.format('%d IP ban authorization tests PASS', total))
