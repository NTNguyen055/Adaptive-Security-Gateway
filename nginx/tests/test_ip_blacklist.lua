-- Stage 1.4 batch 3: IP blacklist manual/auto lifecycle and Redis-outage mocks.
-- Usage: luajit test_ip_blacklist.lua /tmp/ip_blacklist_14.lua
local source = (arg and arg[1]) or "nginx/lua/ip_blacklist.lua"
local ip = "192.0.2.42"
local state = {}
ngx = {
  WARN=4, ERR=3, INFO=6, NOTICE=5, null={},
  var={realip_remote_addr=ip, remote_addr=ip},
  log=function(...) end,
  shared={}
}
local cache = {items={}, ttls={}}
function cache:get(key) return self.items[key] end
function cache:set(key,value,ttl)
  self.items[key]=value
  self.ttls[key]=ttl
  return true
end
ngx.shared.ip_cache=cache
local red={}
function red:init_pipeline() state.pipe={} end
function red:sismember(key,value) state.pipe[#state.pipe+1] = {"sismember",key,value} end
function red:get(key) state.pipe[#state.pipe+1] = {"get",key} end
function red:commit_pipeline()
  if state.fail_pipeline then return nil, "timeout" end
  if state.invalid_replies then return state.invalid_replies end
  assert(#state.pipe==2, "expected exactly two pipelined commands")
  assert(state.pipe[1][2]=="blacklist_ips" and state.pipe[1][3]==ip)
  assert(state.pipe[2][2]=="blacklist:"..ip)
  return {state.manual and 1 or 0, state.auto and "1" or ngx.null}
end
function red:close() state.closed=state.closed+1 end
function red:srem() error("Blacklist may not silently erase manual ban") end
package.loaded["redis_helper"]={
  get_redis=function(db)
    assert(db==0)
    state.connects=state.connects+1
    if state.unavailable then return nil,"unavailable" end
    return red
  end,
  close=function(_) state.pooled=state.pooled+1 end,
}
metric_blocked=nil
local module=assert(loadfile(source))()
local passed,failed=0,0
local function check(cond,msg) if not cond then error(msg,2) end end
local function reset()
  state={manual=false,auto=false,unavailable=false,fail_pipeline=false,
         invalid_replies=nil,connects=0,pooled=0,closed=0,pipe={}}
  cache.items={};cache.ttls={}
  ngx.var={realip_remote_addr=ip,remote_addr=ip}
end
local function request()
  local ctx={security={risk=12,signals={}}}
  module.run(ctx)
  return ctx.security
end
local function case(name,fn)
  reset()
  local ok,err=pcall(fn)
  if ok then passed=passed+1;print("PASS  "..name)
  else failed=failed+1;print("FAIL  "..name..": "..tostring(err)) end
end
case("clean IP is allowed and cached negatively",function()
  local s=request()
  check(not s.block and s.risk==12, "clean IP not allowed")
  check(cache.items["bl:"..ip]==0 and cache.ttls["bl:"..ip]==5,"negative cache missing")
  check(state.pooled==1,"healthy connection not pooled")
end)
case("negative cache hit skips Redis",function()
  request();request()
  check(state.connects==1,"cache miss unexpectedly repeated")
end)
case("automatic TTL key blocks without a persistent manual SET",function()
  state.auto=true
  local s=request()
  check(s.block and s.ip_blacklisted and s.risk==100,"automatic ban not enforced")
  check(s.signals[1]=="ip_blacklist_auto","auto ban signal wrong")
  check(cache.items["bl:"..ip]==1,"positive cache missing")
end)
case("expired automatic key allows request when no manual ban",function()
  state.auto=true;request()
  state.auto=false
  local s=request()
  check(not s.block and s.risk==12,"expired automatic ban persisted")
  check(cache.items["bl:"..ip]==0,"positive cache not cleared")
end)
case("manual SET membership alone blocks persistently",function()
  state.manual=true
  local s=request()
  check(s.block and s.signals[1]=="ip_blacklist_manual","manual ban ignored")
end)
case("manual ban takes precedence when auto TTL also exists",function()
  state.manual=true;state.auto=true
  local s=request()
  check(s.block and s.signals[1]=="ip_blacklist_manual","manual classification lost")
end)
case("manual unban becomes effective on positive cache revalidation",function()
  state.manual=true;request()
  state.manual=false
  local s=request()
  check(not s.block,"manual unban not honored")
  check(state.connects==2,"positive cache must revalidate")
end)
case("Redis outage on cache miss never increases client Risk",function()
  state.unavailable=true
  local s=request()
  check(not s.block and s.risk==12 and s.redis_bl_fail,"outage punished client IP")
  check(state.pooled==0,"failed connection pooled")
end)
case("Redis outage with previously positive cache stays blocked",function()
  state.manual=true;request()
  state.unavailable=true
  local s=request()
  check(s.block and s.redis_bl_fail,"cached ban not preserved")
  check(s.signals[1]=="ip_blacklist_cached","expected cached-ban signal")
end)
case("pipeline failure on cache miss is not treated as clean",function()
  state.fail_pipeline=true
  local s=request()
  check(not s.block and s.risk==12 and s.redis_bl_error,"pipeline error mishandled")
  check(cache.items["bl:"..ip]==nil,"error must not poison negative cache")
  check(state.closed==1 and state.pooled==0,"broken connection must be closed")
end)
case("pipeline failure after positive cache conservatively blocks",function()
  state.auto=true;request()
  state.fail_pipeline=true
  local s=request()
  check(s.block and s.redis_bl_error,"positive cached block lost")
end)
case("invalid Redis EVAL-like replies cannot be interpreted as clean",function()
  state.invalid_replies={false,ngx.null}
  local s=request()
  check(s.redis_bl_error and not s.block,"invalid manual membership accepted")
  check(cache.items["bl:"..ip]==nil,"invalid reply cached")
end)
case("negative-cache window is bounded to 5 seconds",function()
  request()
  state.manual=true
  local s=request()
  check(not s.block,"negative cache behavior unexpectedly changed")
  check(cache.ttls["bl:"..ip]==5,"negative TTL not bounded")
end)
print(string.format("IP blacklist lifecycle tests: %d passed, %d failed, %d total",passed,failed,passed+failed))
if failed>0 then os.exit(1) end
