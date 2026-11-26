-- Shadow integration contract tests: zero live enforcement, no network or Redis.
-- Run from the repository root: luajit nginx/tests/test_security_shadow.lua
package.path = "nginx/lua/?.lua;" .. package.path
local logs = {}
local config = {SECURITY_SHADOW_ENABLED="true", SECURITY_SHADOW_LOG_ALL="false"}
local original_getenv = os.getenv
os.getenv = function(k) return config[k] or original_getenv(k) end
_G.ngx = {
    WARN=4, ERR=3, INFO=2, ctx={}, status=200,
    var={uri="/",request_id="test-request-1",log_security_reason="-"},
    log=function(level,...)
        local chunks={...}
        for i,v in ipairs(chunks) do chunks[i]=tostring(v) end
        logs[#logs+1] = table.concat(chunks)
    end,
    exit=function() error("shadow must not call ngx.exit") end,
    header={},
}
local shadow = assert(require("security_shadow"))
local total = 0
local function check(name, assertion)
    assert(assertion,name)
    total=total+1
    print("PASS "..name)
end
local function reset(route, uri)
    ngx.ctx={}; ngx.status=200
    ngx.var.uri=uri or "/"; ngx.var.log_security_reason="-"
    logs={}
    local ctx={security={risk=0,signals={}}}
    shadow.start(ctx, route)
    return ctx
end
local function last_log()
    return logs[#logs] or ""
end
local waf={run=function(ctx)
    ctx.security.waf_sqli=true
    ctx.security.block=true
    ctx.security.signals[#ctx.security.signals+1]="waf_sqli"
end}
local rl={run=function(ctx)
    ctx.security.block=true
    ctx.security.rate_limit_hard=true
    ctx.security.signals[#ctx.security.signals+1]="rate_limit_hard"
end}
local jwt={run=function(ctx)
    ctx.security.jwt_valid=true
end}
local bad={run=function(ctx)
    ctx.security.ua_unknown=true
    ctx.security.signals[#ctx.security.signals+1]="ua_unknown"
    return nil,"hello",false
end}
local private_xff = {
    run = function(ctx)
        ctx.security.xff_private_client = true
        ctx.security.signals[#ctx.security.signals + 1] =
            "xff_private_client"
    end
}

local private_geo = {
    run = function(ctx)
        ctx.security.geo_private = true
        ctx.security.signals[#ctx.security.signals + 1] =
            "geo_private"
    end
}

local clean_waf = {
    run = function(ctx)
        -- No WAF finding.
    end
}
local failing={run=function() error("mock required control failure") end}
local optional_fail={run=function() error("mock optional failure") end}
shadow.register({
    [waf]="waf_sqli_xss",
    [rl]="rate_limit",
    [jwt]="jwt_auth",
    [bad]="bad_bot",
    [failing]="waf_sqli_xss",
    [optional_fail]="rate_limit_redis",
    [private_xff] = "xff_guard",
    [private_geo] = "geo_block",
    [clean_waf] = "waf_sqli_xss",
},function(uri) return uri=="/api/private" end)

-- Disabled mode must not instrument or change legacy pcall behavior.
config.SECURITY_SHADOW_ENABLED="false"
local ctx=reset("main","/api/private")
check("disabled: no trace", ngx.ctx.asg_security_shadow==nil)
local ok,a,b,c=shadow.run(bad,ctx)
check("disabled: pcall return tuple preserved",ok and a==nil and b=="hello" and c==false)
shadow.log()
check("disabled: no logging",#logs==0)
config.SECURITY_SHADOW_ENABLED="true"

ctx=reset("main","/")
check("enabled: trace created",ngx.ctx.asg_security_shadow~=nil)
local result=shadow.run(waf,ctx)
check("WAF: legacy pcall success",result==true)
ngx.var.log_security_reason="waf_sqli"; ngx.status=403
shadow.log()
check("WAF: no shadow false mismatch",#logs==0)
check("WAF: no live status change",ngx.status==403 and ctx.security.block==true)
check("WAF: trace released",ngx.ctx.asg_security_shadow==nil)

ctx=reset("main","/")
shadow.run(rl,ctx)
ctx.security.risk_action="limit"; ctx.security.rate_only_limited=true
ngx.var.log_security_reason="rate_limit_hard"; ngx.status=429
shadow.log()
check("rate-only: shadow agrees with live 429",#logs==0 and ngx.status==429)

ctx=reset("main","/api/private")
shadow.run(jwt,ctx)
shadow.run(waf,ctx)
ngx.var.log_security_reason="waf_sqli"; ngx.status=403
shadow.log()
check("protected JWT+WAF: no mismatch",#logs==0)

ctx=reset("main","/")
local success, err = shadow.run(failing,ctx)
check("required failure: legacy pcall false preserved",success==false and type(err)=="string")
ngx.status=200
shadow.log()
check("required failure: divergence logged, not enforced",last_log():find("policy_action=UNAVAILABLE",1,true)~=nil and ngx.status==200)
check("required failure: status difference logged",last_log():find("status_diff=true",1,true)~=nil)

ctx=reset("dologin","/doLogin/")
local okfail = shadow.run(optional_fail,ctx)
check("optional failure: legacy pcall preserved",okfail==false)
shadow.log()
check("optional failure: error observed without denial",last_log():find("errors=1",1,true)~=nil and ngx.status==200)
check("optional failure exposes error code", last_log():find("error_codes=rate_limit_redis:module_crash", 1, true) ~= nil)

ctx=reset("login","/login/")
shadow.prelogin(true,true)
ngx.status=403
shadow.log()
check("prelogin early 403: logged",last_log():find("legacy_status=403",1,true)~=nil)
check("prelogin early 403: partial",last_log():find("partial=true",1,true)~=nil)

ctx=reset("login","/login/")
shadow.prelogin(false,nil)
ngx.status=503
shadow.log()
check("prelogin failed: logged 503",last_log():find("legacy_status=503",1,true)~=nil)

ctx=reset("dologin","/doLogin/")
local ok1,ret1,ret2,ret3=shadow.run(bad,ctx)
check("enabled: return tuple including nil preserved",ok1 and ret1==nil and ret2=="hello" and ret3==false)
shadow.log()

config.SECURITY_SHADOW_LOG_ALL="true"

ctx = reset("main", "/profile/")

shadow.run(private_xff, ctx)
shadow.run(private_geo, ctx)
shadow.run(clean_waf, ctx)

ngx.status = 302
shadow.log()

check(
    "private profile has zero normalization errors",
    last_log():find("errors=0", 1, true) ~= nil
)

check(
    "private profile has complete shadow coverage",
    last_log():find("partial=false", 1, true) ~= nil
)

ctx=reset("assets","/static/main.css")
shadow.log()
check("log all: clean comparison emitted",last_log():find("route=assets",1,true)~=nil)
config.SECURITY_SHADOW_LOG_ALL="false"

-- No test can call Redis or Telegram: those services are not mocked/loaded.
os.getenv=original_getenv
print(string.format("%d security shadow integration tests PASS",total))
