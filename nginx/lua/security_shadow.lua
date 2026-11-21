-- P0.2.4-A2: observation-only integration of the unified security policy.
-- No Redis, ngx.exit, HTTP header/body writes, Telegram or blacklist writes.
-- Gateway module calls and their pcall return values must remain unchanged.
local adapter = require "security_signal_adapter"
local correlator = require "security_correlator"
local M = {}
local unpack = table.unpack or unpack
local modules = {}
local jwt_required_for_uri = nil

local function pack(...)
    return {n = select("#", ...), ...}
end

local function enabled()
    return (os.getenv("SECURITY_SHADOW_ENABLED") or "false"):lower() == "true"
end

local function log_error(message)
    -- Never propagate a shadow instrumentation error into live enforcement.
    pcall(ngx.log, ngx.ERR, "[SECURITY_SHADOW] ", tostring(message))
end

-- Called from trusted init_by_lua_block, never from client-supplied data.
function M.register(module_map, jwt_classifier)
    assert(type(module_map) == "table", "shadow module map missing")
    assert(type(jwt_classifier) == "function", "shadow JWT classifier missing")
    modules = module_map
    jwt_required_for_uri = jwt_classifier
end

-- route: assets | login | dologin | admin | main
function M.start(ctx, route)
    if not enabled() then return end
    local ok, err = pcall(function()
        local modes = {
            assets = "assets", login = "login", dologin = "standard",
            admin = "standard", main = "standard",
        }
        local route_mode = modes[route]
        assert(route_mode ~= nil, "unknown shadow route")
        assert(type(jwt_required_for_uri) == "function", "JWT classifier unavailable")
        assert(type(ctx) == "table" and type(ctx.security) == "table", "missing context")
        local jwt_required = (route == "main" or route == "admin")
            and jwt_required_for_uri(ngx.var.uri) or false
        assert(type(jwt_required) == "boolean", "invalid JWT route classification")
        local required = {}
        if jwt_required then required.jwt_auth = true end
        if route == "admin" or route == "main" then
            required.waf_sqli_xss = true
        end
        local trace, problem = adapter.new({
            jwt_required = jwt_required,
            route_mode = route_mode,
            required_modules = required,
        })
        assert(trace, problem or "could not create shadow trace")
        ngx.ctx.asg_security_shadow = {
            trace = trace, ctx = ctx, route = route, prelogin = nil,
            instrumentation_error = nil,
        }
    end)
    if not ok then log_error(err) end
end

-- Preserve all values from pcall, including nils.
-- This replaces only `pcall(m.run, ctx)` in the existing access-phase loops.
function M.run(module, ctx)
    local state = ngx.ctx.asg_security_shadow
    if not state then return pcall(module.run, ctx) end
    local name = modules[module]
    local step
    if name then
        local ok, result, problem = pcall(adapter.begin_step, state.trace, name, ctx)
        if ok and result then
            step = result
        else
            state.instrumentation_error = "begin_step_failed"
            log_error(problem or result)
        end
    else
        state.instrumentation_error = "unregistered_module"
        log_error("unregistered_module")
    end

    local result = pack(pcall(module.run, ctx))
    if step then
        local ok, ended, problem = pcall(adapter.end_step, state.trace, step, ctx, result[1])
        if not ok or not ended then
            state.instrumentation_error = "end_step_failed"
            log_error(problem or ended)
        end
    end
    return unpack(result, 1, result.n)
end

-- Record early exits from check_prelogin() without changing its decision.
function M.prelogin(call_ok, locked)
    local state = ngx.ctx.asg_security_shadow
    if not state then return end
    if not call_ok or locked == nil then
        state.prelogin = "unavailable"
    elseif locked == true then
        state.prelogin = "locked"
    else
        state.prelogin = "passed"
    end
end

local function normalized_reason(reason)
    if reason == "ip_blacklist_auto" then return "ip_blacklist_automatic" end
    return reason
end

-- Called once per request from log_by_lua_block, including ngx.exit early exits.
function M.log()
    local state = ngx.ctx.asg_security_shadow

    if not state then return end

    ngx.ctx.asg_security_shadow = nil

    local ok, err = pcall(function()
        local legacy_reason = ngx.var.log_security_reason
        -- A previously denied request legitimately short-circuits later modules.
        -- Do not treat "not reached" as a missing mandatory control, but keep
        -- the report explicitly partial. On a clean path, missing JWT/WAF is 503.
        local skipped_required = false

        if state.ctx.security.block == true then
            for name in pairs(state.trace.required) do
                if not state.trace.seen[name] then
                    state.trace.required[name] = nil
                    skipped_required = true
                end
            end
        end

        local report, problem = adapter.finish(state.trace, state.ctx)
        if not report then
            log_error("adapter_finish_failed: " .. tostring(problem))
            return
        end

        if (os.getenv("SECURITY_CORRELATOR_SHADOW_ENABLED") or "false"):lower() == "true" then
            local call_ok, summary, correlation_err = pcall(
                correlator.observe,
                {
                    trace = state.trace,
                    peer_ip = ngx.var.remote_addr,
                    request_id = ngx.var.request_id,

                    -- Missing downstream JWT due to a confirmed WAF block does
                    -- not invalidate the WAF observation itself.
                    -- Only a completed, correctly attributed WAF step is eligible.
                    partial = state.instrumentation_error ~= nil
                        or state.trace.required_control_failed == true
                        or #report.errors > 0
                        or state.trace.seen.waf_sqli_xss ~= true,
                }
            )

            if not call_ok then
                log_error("correlator_crashed")

            elseif not summary then
                log_error(
                    "correlator_error: " .. tostring(correlation_err)
                )

            elseif summary.notify then
                ngx.log(
                    ngx.WARN,
                    "[SECURITY_CORRELATOR] status=SUSPICIOUS_SHADOW",
                    " events=", summary.event_count,
                    " windows=", summary.distinct_windows,
                    " classes=", summary.distinct_attack_classes,
                    " automatic_ban=disabled"
                )
            end
        end

        local policy = report.policy
        local old_action, old_status = report.legacy_action, report.legacy_status

        if state.prelogin == "locked" then
            old_action, old_status = "BLOCK_REQUEST", 403
        elseif state.prelogin == "unavailable" then
            old_action, old_status = "UNAVAILABLE", 503
        end

        local status_diff = (old_status ~= policy.http_status)
        local action_diff = (old_action ~= policy.action)
        -- Some legacy reasons (risk_block/risk_limit/other) have no deterministic
        -- policy equivalent; report them as unmapped, not as mismatches.
        local comparable = type(legacy_reason) == "string"
            and legacy_reason ~= "-" and legacy_reason ~= ""
            and legacy_reason ~= "risk_block" and legacy_reason ~= "risk_limit"
            and legacy_reason ~= "other"
        local reason_diff = comparable and
            (normalized_reason(legacy_reason) ~= policy.reason) or false
        local unmapped = not comparable and old_status ~= nil
        local partial = skipped_required
            or state.prelogin == "locked" or state.prelogin == "unavailable"
            or (state.trace.required_control_failed == true)
            or (#report.errors > 0)
        for module in pairs(state.trace.required) do
            if not state.trace.seen[module] then partial = true end
        end

        local has_error = state.instrumentation_error ~= nil or #report.errors > 0
        local verbose = (os.getenv("SECURITY_SHADOW_LOG_ALL") or "false"):lower() == "true"

        if not (verbose or status_diff or action_diff or reason_diff or has_error or unmapped) then
            return
        end

        local final_http = tonumber(ngx.status) or 0

        local error_codes = {}

        for index, item in ipairs(report.errors) do
            if index > 8 then
                error_codes[#error_codes + 1] = "truncated"
                break
            end

            error_codes[#error_codes + 1] =
                tostring(item.module) .. ":" .. tostring(item.code)
        end

        -- No IP, request URI/query string, Authorization or raw User-Agent in logs.
        ngx.log(ngx.WARN,
            "[SECURITY_SHADOW] route=", state.route,
            " request_id=", tostring(ngx.var.request_id or "-"),
            " legacy_action=", old_action,
            " legacy_status=", tostring(old_status or "forward"),
            " legacy_reason=", tostring(legacy_reason or "-"),
            " policy_action=", policy.action,
            " policy_status=", tostring(policy.http_status or "forward"),
            " policy_reason=", policy.reason,
            " status_diff=", tostring(status_diff),
            " action_diff=", tostring(action_diff),
            " reason_diff=", comparable and tostring(reason_diff) or "unmapped",
            " partial=", tostring(partial),
            " errors=", #report.errors,
            " error_codes=", (#error_codes > 0)
                and table.concat(error_codes, ",") or "-",
            " final_http=", final_http
        )
    end)

    if not ok then log_error(err) end
end

return M
