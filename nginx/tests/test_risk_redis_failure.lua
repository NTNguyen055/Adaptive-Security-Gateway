-- Stage 1.4 batch 3: Risk Engine infrastructure failure must not punish IP.
-- Usage: luajit test_risk_redis_failure.lua /tmp/risk_engine_14.lua
local source=(arg and arg[1]) or "nginx/lua/risk_engine.lua"
-- Force deterministic decay behavior regardless of gateway env.local values.
local original_getenv = os.getenv
os.getenv = function(name)
  if name == "RISK_DECAY_ENABLED" then return "true" end
  if name == "RISK_DECAY_FACTOR" then return "0.1" end
  return original_getenv(name)
end
local ip="192.0.2.87"
local state={}
ngx={ERR=3,WARN=4,INFO=6,null={},now=function() return 1000 end,
  var={realip_remote_addr=ip,remote_addr=ip},log=function(...) end}
local red={}
function red:get(key)
  state.reads=state.reads+1
  if state.fail_read_key==key then return nil,"read timeout" end
  return state.kv[key] or ngx.null
end
function red:set(key,val,...)
  state.writes=state.writes+1
  if state.fail_write_key==key then return nil,"write timeout" end
  state.kv[key]=val
  return "OK"
end
function red:sadd() error("Risk Engine must not write to persistent manual SET") end
function red:close() state.closed=state.closed+1 end

-- Simulate atomic EVAL: a failed write cannot partially update keys.
function red:eval(script,nkeys,score_key,stamp_key,ban_key, bf_key,score,ttl,stamp,has_stamp,has_ban,ban_ttl)
  assert(type(script)=="string" and nkeys==4)
  if state.fail_write_key==score_key or
      (tonumber(has_stamp)==1 and state.fail_write_key==stamp_key) or
      (tonumber(has_ban)==1 and state.fail_write_key==ban_key) then
    return nil,"write timeout"
  end
  self:set(score_key,score,"EX",ttl)
  if tonumber(has_stamp)==1 then self:set(stamp_key,stamp,"EX",ttl) end
  if tonumber(has_ban)==1 then self:set(ban_key,"1","EX",ban_ttl) end
  return 1
end

package.loaded["redis_helper"]={
  get_redis=function(db)
    assert(db==0)
    state.connects=state.connects+1
    if state.unavailable then return nil,"connection refused" end
    return red
  end,
  close=function(_) state.pooled=state.pooled+1 end,
}
package.loaded["telegram_alert"]={send=function(_) state.alerts=state.alerts+1 end}
metric_blocked=nil
local module=assert(loadfile(source))()
local passed,failed=0,0
local function check(cond,msg) if not cond then error(msg,2) end end
local function reset()
  state={kv={},reads=0,writes=0,connects=0,closed=0,pooled=0,alerts=0,
         unavailable=false,fail_read_key=nil,fail_write_key=nil}
  ngx.var={realip_remote_addr=ip,remote_addr=ip}
end
local function abuse(risk, preblocked)
  return {security={client_ip=ip,risk=risk,block=preblocked,
          bad_bot_scanner=true,signals={"bad_bot_scanner"}}}
end
local function case(name,fn)
  reset()
  local ok,err=pcall(fn)
  if ok then passed=passed+1;print("PASS  "..name)
  else failed=failed+1;print("FAIL  "..name..": "..tostring(err)) end
end
case("Redis connect failure preserves strong request block without IP writes",function()
  state.unavailable=true
  local ctx=abuse(75,true) -- +10 scanner => 85
  module.run(ctx)
  check(ctx.security.risk_action=="block" and ctx.security.redis_risk_fail,"fallback strong block missing")
  check(ctx.security.risk_final==85 and state.writes==0 and state.alerts==0,"outage unexpectedly persisted ban")
  check(ngx.var.log_security_block=="block","log action missing")
end)
case("Redis outage with moderate risk keeps request-only limit",function()
  state.unavailable=true
  local ctx=abuse(45,false) -- 55
  module.run(ctx)
  check(ctx.security.risk_action=="limit" and not ctx.security.block,"fallback limit wrong")
end)
case("Redis outage does not punish a low-risk request",function()
  state.unavailable=true
  local ctx=abuse(5,false) -- 15
  module.run(ctx)
  check(ctx.security.risk_action=="pass" and ctx.security.risk_final==15,"low risk punished")
end)
case("Redis outage preserves upstream security block",function()
  state.unavailable=true
  local ctx=abuse(5,true)
  module.run(ctx)
  check(ctx.security.block and ctx.security.risk_action=="block","pre-existing block bypassed")
end)
case("reputation read failure is not interpreted as zero",function()
  state.fail_read_key="risk:v1:"..ip
  local ctx=abuse(35,false)
  module.run(ctx)
  check(ctx.security.redis_risk_error and ctx.security.risk_final==45,"read failure silently accepted")
  check(state.closed==1 and state.pooled==0,"broken connection should be discarded")
  check(state.writes==0,"read failure wrote reputation")
end)
case("malformed stored reputation cannot overwrite old score",function()
  state.kv["risk:v1:"..ip]="unexpected"
  local ctx=abuse(45,false)
  module.run(ctx)
  check(ctx.security.redis_risk_error and state.writes==0,"malformed score silently reset")
end)
case("timestamp read failure cannot silently disable time decay",function()
  state.kv["risk:v1:"..ip]="40.00"
  state.fail_read_key="risk:v1:last_seen:"..ip
  local ctx=abuse(45,false)
  module.run(ctx)
  check(ctx.security.redis_risk_error and state.writes==0,"timestamp failure treated as missing")
end)
case("brute-force history read failure cannot silently be ignored",function()
  state.fail_read_key="brute_force:history:"..ip
  local ctx=abuse(45,false)
  module.run(ctx)
  check(ctx.security.redis_risk_error and state.writes==0,"history read failure ignored")
end)
case("reputation write failure does not create a detached blacklist",function()
  state.fail_write_key="risk:v1:"..ip
  local ctx=abuse(75,true)
  module.run(ctx)
  check(ctx.security.risk_action=="block" and ctx.security.redis_risk_error,"write failure action lost")
  check(state.kv["blacklist:"..ip]==nil and state.kv["risk:v1:last_seen:"..ip]==nil,
        "detached write after failed reputation update")
end)
case("atomic temporary-ban failure leaves no partial reputation and preserves request block",function()
  state.fail_write_key="blacklist:"..ip
  local ctx=abuse(75,true)
  module.run(ctx)
  check(ctx.security.block and ctx.security.risk_action=="block","failed ban write allowed request")
  check(ctx.security.redis_risk_error,"ban write failure hidden")
  check(state.kv["risk:v1:"..ip]==nil and state.kv["risk:v1:last_seen:"..ip]==nil,
        "failed atomic transaction left partial reputation/timestamp")
end)
case("context-only request never opens Redis even when unavailable",function()
  state.unavailable=true
  local ctx={security={client_ip=ip,risk=20,signals={"dev_tool"}}}
  module.run(ctx)
  check(ctx.security.risk_action=="pass" and state.connects==0,"context-only accessed Redis")
end)
print(string.format("Risk Redis failure tests: %d passed, %d failed, %d total",passed,failed,passed+failed))
if failed>0 then os.exit(1) end
