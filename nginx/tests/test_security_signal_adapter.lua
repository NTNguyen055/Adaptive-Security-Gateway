-- P0.2.4-A2: pure-Lua passive normalization / provenance / shadow tests.
-- No OpenResty, network, Redis, real IP bans, or credentials required.
package.path = "nginx/lua/?.lua;" .. package.path
local adapter = assert(require("security_signal_adapter"))
local total = 0

local function yes(label, value)
    assert(value, label)
    total = total + 1
    print("PASS " .. label)
end
local function scenario(label, opts, steps, expected, status, reason)
    local trace, new_err = adapter.new(opts or {jwt_required=false})
    assert(trace, label .. ": " .. tostring(new_err))
    local ctx = {security={signals={}, risk=0}}
    for _, step in ipairs(steps) do
        local before, err = adapter.begin_step(trace, step.module, ctx)
        assert(before, label .. " begin: " .. tostring(err))
        if step.mutate then step.mutate(ctx.security) end
        local ok, msg = adapter.end_step(trace, before, ctx, step.success ~= false)
        assert(ok, label .. " end: " .. tostring(msg))
    end
    local report, err = adapter.finish(trace, ctx)
    assert(report, label .. " finish: " .. tostring(err))
    assert(report.policy.action == expected,
        label .. ": action " .. tostring(report.policy.action) .. ", expected " .. expected)
    assert(report.policy.http_status == status,
        label .. ": HTTP " .. tostring(report.policy.http_status))
    if reason then assert(report.policy.reason == reason, label .. ": reason " .. report.policy.reason) end
    assert(report.policy.create_ip_ban == false, label .. ": evaluator minted IP ban")
    total = total + 1
    print("PASS " .. label)
    return report, ctx
end
local function emit(id, flag, block)
    return function(s)
        if flag then s[flag]=true end
        if block then s.block=true end
        if id then s.signals[#s.signals+1]=id end
    end
end

scenario("A2 clean optional module", nil, {{module="xff_guard"}}, "ALLOW", nil)
scenario("A2 WAF SQLi flag+raw", nil, {{module="waf_sqli_xss",mutate=emit("waf_sqli","waf_sqli",true)}}, "BLOCK_REQUEST",403,"waf_sqli")
scenario("A2 WAF XSS flag-only", nil, {{module="waf_sqli_xss",mutate=emit(nil,"waf_xss",true)}}, "BLOCK_REQUEST",403,"waf_xss")
scenario("A2 scanner annotated", nil, {{module="bad_bot",mutate=emit("bad_bot_scanner:sqlmap","bad_bot_scanner",true)}}, "BLOCK_REQUEST",403,"bad_bot_scanner")
scenario("A2 headless annotated", nil, {{module="bad_bot",mutate=emit("bad_bot_headless:playwright","bad_bot_headless",false)}}, "THROTTLE",429)
scenario("A2 unknown UA", nil, {{module="bad_bot",mutate=emit("ua_unknown:cached","ua_unknown",false)}}, "OBSERVE",nil)
scenario("A2 XFF spoof observe", nil, {{module="xff_guard",mutate=emit("xff_spoof","xff_spoof",false)}}, "OBSERVE",nil)
scenario("A2 XFF chain request block", nil, {{module="xff_guard",mutate=emit("xff_chain_abuse","xff_chain_abuse",true)}}, "BLOCK_REQUEST",403)
scenario("A2 geo annotated country", nil, {{module="geo_block",mutate=emit("geo_block:CN","geo_blocked",true)}}, "BLOCK_REQUEST",403,"geo_block")
scenario("A2 geo flag-only", nil, {{module="geo_block",mutate=emit(nil,"geo_blocked",true)}}, "BLOCK_REQUEST",403)
scenario("A2 rate local", nil, {{module="rate_limit",mutate=emit("rate_limit_hard","rate_limit_hard",true)}}, "THROTTLE",429)
scenario("A2 rate-only 429", nil, {{module="rate_limit",mutate=function(s) emit("rate_limit_hard","rate_limit_hard",true)(s); s.rate_only_limited=true end}}, "THROTTLE",429)
scenario("A2 Redis rate-only", nil, {{module="rate_limit_redis",mutate=function(s) emit("redis_rate_exceeded","redis_rate_exceeded",true)(s); s.rate_only_limited=true end}}, "THROTTLE",429)
scenario("A2 WAF outranks rate", nil, {
    {module="rate_limit",mutate=emit("rate_limit_burst","rate_limit_burst",true)},
    {module="waf_sqli_xss",mutate=emit("waf_sqli","waf_sqli",true)},
}, "BLOCK_REQUEST",403,"waf_sqli")
scenario("A2 verified manual blacklist",nil,{{module="ip_blacklist",mutate=emit("ip_blacklist_manual","ip_blacklisted",true)}},"DENY_IP",403,"ip_blacklist_manual")
scenario("A2 verified automatic blacklist",nil,{{module="ip_blacklist",mutate=emit("ip_blacklist_auto","ip_blacklisted",true)}},"DENY_IP",403,"ip_blacklist_automatic")
scenario("A2 cached positive from Redis outage",nil,{{module="ip_blacklist",mutate=emit("ip_blacklist_cached","ip_blacklisted",true)}},"BLOCK_REQUEST",403,"ip_blacklist_cached")
scenario("A2 IP flag without verified origin",nil,{{module="ip_blacklist",mutate=emit(nil,"ip_blacklisted",true)}},"BLOCK_REQUEST",403,"unmapped_detector_block")
scenario("A2 invalid JWT",{jwt_required=true, required_modules={jwt_auth=true}},{{module="jwt_auth",mutate=emit("jwt_invalid","jwt_invalid",true)}},"BLOCK_REQUEST",403)
scenario("A2 JWT missing",{jwt_required=true, required_modules={jwt_auth=true}},{{module="jwt_auth",mutate=emit("jwt_missing","jwt_missing",true)}},"BLOCK_REQUEST",403)
scenario("A2 JWT verified",{jwt_required=true, required_modules={jwt_auth=true}},{{module="jwt_auth",mutate=function(s) s.jwt_valid=true end}},"ALLOW",nil)
scenario("A2 JWT changed IP re-auth",{jwt_required=true, required_modules={jwt_auth=true}},{{module="jwt_auth",mutate=emit("jwt_replay","jwt_replay",true)}},"REAUTH_SESSION",401)
scenario("A2 JWT config error fail closed",{jwt_required=true,required_modules={jwt_auth=true}},{{module="jwt_auth",mutate=function(s) s.jwt_config_error=true; s.block=true end}},"UNAVAILABLE",503)
scenario("A2 JWT module crash fail closed",{jwt_required=true,required_modules={jwt_auth=true}},{{module="jwt_auth",success=false}},"UNAVAILABLE",503)
scenario("A2 JWT required but skipped",{jwt_required=true,required_modules={jwt_auth=true}},{},"UNAVAILABLE",503)
scenario("A2 required WAF crash fail closed",{jwt_required=false,required_modules={waf_sqli_xss=true}},{{module="waf_sqli_xss",success=false}},"UNAVAILABLE",503)
scenario("A2 optional Redis limiter fail records error",nil,{{module="rate_limit_redis",success=false}},"ALLOW",nil)
scenario("A2 fallback preserves module block",nil,{{module="bad_bot",mutate=function(s) s.block=true end}},"BLOCK_REQUEST",403,"unmapped_detector_block")
scenario("A2 brute force legacy signal",nil,{{module="brute_force_login",mutate=emit("brute_force_attack",nil,true)}},"BLOCK_REQUEST",403)
scenario("A2 future account backoff",nil,{{module="login_accounting",mutate=emit("auth_account_backoff","auth_account_backoff",false)}},"ACCOUNT_RESTRICT",429)
scenario("A2 future ML anomaly observe",nil,{{module="ml_detector",mutate=emit("ml_anomaly","ml_anomaly",false)}},"OBSERVE",nil)
scenario("A2 context-only Redis degraded",nil,{{module="rate_limit_redis",mutate=function(s) s.redis_rl_fail=true end}},"ALLOW",nil)

scenario("A2 partial block followed by module crash stays denied",nil,
    {{module="bad_bot",success=false,mutate=function(s) s.block=true end}},
    "BLOCK_REQUEST",403,"unmapped_detector_block")
scenario("A2 no ban from manual label without block",nil,
    {{module="ip_blacklist",mutate=function(s) s.ip_blacklisted=true; s.signals[1]="ip_blacklist_manual" end}},
    "UNAVAILABLE",503)
scenario("A2 conflicting ban origins fail closed",nil,
    {{module="ip_blacklist",mutate=function(s)
        s.ip_blacklisted=true; s.block=true
        s.signals={"ip_blacklist_manual", "ip_blacklist_auto"}
    end}},"UNAVAILABLE",503)

-- Legacy decision comparison must use the actual Nginx location semantics.
local assets, asset_err = adapter.new({jwt_required=false,route_mode="assets"})
assert(assets,asset_err)
local asset_report=assert(adapter.finish(assets,{security={risk_action="limit",risk=55}}))
yes("A2 assets location ignores limit-only legacy action",asset_report.legacy_status==nil)
local login, login_err = adapter.new({jwt_required=false,route_mode="login"})
assert(login,login_err)
local login_report=assert(adapter.finish(login,{security={block=true,rate_only_limited=true,risk_action="limit",risk=55}}))
yes("A2 login location lacks rate-only 429 override",login_report.legacy_status==403)
local main=assert(adapter.new({jwt_required=false,route_mode="standard"}))
local main_report=assert(adapter.finish(main,{security={block=true,rate_only_limited=true,risk_action="limit",risk=55}}))
yes("A2 standard location retains rate-only 429 override",main_report.legacy_status==429)
local bad_route,bad_err=adapter.new({jwt_required=false,route_mode="unexpected"})
yes("A2 unknown route mode rejected",bad_route==nil and bad_err=="invalid_route_mode")

local invalid, err = adapter.new({jwt_required="no"})
yes("A2 reject untrusted route config", invalid==nil and err=="invalid_route_config")
invalid,err=adapter.new({jwt_required=false,required_modules={not_real=true}})
yes("A2 reject unknown required module", invalid==nil and err=="invalid_required_module")
local trace=assert(adapter.new({jwt_required=false}))
local ctx={security={signals={}}}
local step=assert(adapter.begin_step(trace,"bad_bot",ctx))
invalid,err=adapter.begin_step(trace,"waf_sqli_xss",ctx)
yes("A2 nested step rejected", invalid==nil and err=="duplicate_or_nested_module")
assert(adapter.end_step(trace,step,ctx,true))
invalid,err=adapter.begin_step(trace,"bad_bot",ctx)
yes("A2 duplicate producer rejected", invalid==nil and err=="duplicate_or_nested_module")
local report=assert(adapter.finish(trace,ctx))
yes("A2 clean report still allows",report.policy.action=="ALLOW")

trace=assert(adapter.new({jwt_required=false}))
ctx={security={signals={"waf_sqli"}}}
step=assert(adapter.begin_step(trace,"bad_bot",ctx))
assert(adapter.end_step(trace,step,ctx,true))
report=assert(adapter.finish(trace,ctx))
yes("A2 historical unobserved WAF signal cannot gain provenance",report.policy.action=="ALLOW")

trace=assert(adapter.new({jwt_required=false}))
ctx={security={signals={}}}
step=assert(adapter.begin_step(trace,"bad_bot",ctx))
ctx.security.signals[1]="waf_sqli"
assert(adapter.end_step(trace,step,ctx,true))
report=assert(adapter.finish(trace,ctx))
yes("A2 forged cross-module WAF signal fail closed",report.policy.action=="UNAVAILABLE")

trace=assert(adapter.new({jwt_required=false}))
ctx={security={signals={}}}
step=assert(adapter.begin_step(trace,"waf_sqli_xss",ctx))
ctx.security.signals[2]="waf_sqli"
assert(adapter.end_step(trace,step,ctx,true))
report=assert(adapter.finish(trace,ctx))
yes("A2 sparse legacy signals fail closed",report.policy.action=="UNAVAILABLE")

trace=assert(adapter.new({jwt_required=false}))
ctx={security={signals={}}}
step=assert(adapter.begin_step(trace,"bad_bot",ctx))
ctx.security.signals[1]="future_benign_signal"
assert(adapter.end_step(trace,step,ctx,true))
report=assert(adapter.finish(trace,ctx))
yes("A2 unknown producer signal never becomes authoritative",report.policy.action=="ALLOW" and #report.errors==1)

trace=assert(adapter.new({jwt_required=false}))
ctx={security={signals={},risk=100, risk_action="block"}}
report=assert(adapter.finish(trace,ctx))
yes("A2 risk-only block visible as divergence, not forced IP penalty",report.status_diff and report.policy.action=="OBSERVE" and report.legacy_status==403)

trace=assert(adapter.new({jwt_required=false}))
ctx={security={signals={},risk=100,block=true}}
report=assert(adapter.finish(trace,ctx))
yes("A2 out-of-band block not falsely attributed to detector",report.status_diff and report.policy.action=="OBSERVE")

print(string.format("%d security signal adapter contract tests PASS",total))
