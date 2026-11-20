-- P0.2.4-A isolated contract tests; run from repository root:
--   luajit nginx/tests/test_security_policy.lua
-- No ngx, Redis, credentials, or live services required.
package.path = "nginx/lua/?.lua;" .. package.path
local policy = assert(require("security_policy"))
local passed = 0

local function event(id, source)
    return {id = id, source = source}
end
local function check(label, input, expected_action, expected_status, expected_scope)
    local actual, err = policy.evaluate(input)
    assert(actual, label .. " returned error: " .. tostring(err))
    assert(actual.action == expected_action, label .. ": action=" .. tostring(actual.action))
    assert(actual.http_status == expected_status, label .. ": status=" .. tostring(actual.http_status))
    assert(actual.scope == expected_scope, label .. ": scope=" .. tostring(actual.scope))
    assert(actual.create_ip_ban == false, label .. ": evaluator must never create an IP ban")
    passed = passed + 1
    print("PASS " .. label)
end
local function invalid(label, input, error_code)
    local result, err = policy.evaluate(input)
    assert(result == nil and err == error_code, label .. ": unexpected " .. tostring(err))
    passed = passed + 1
    print("PASS " .. label)
end

check("clean request", {}, "ALLOW", nil, "request")
check("context-only unknown UA", {signals={event("ua_unknown", "bad_bot")}}, "OBSERVE", nil, "request")
check("WAF SQLi: request only", {signals={event("waf_sqli", "waf_sqli_xss")}, risk_score=100}, "BLOCK_REQUEST", 403, "request")
check("WAF XSS: request only", {signals={event("waf_xss", "waf_sqli_xss")}}, "BLOCK_REQUEST", 403, "request")
check("scanner UA: no automatic ban", {signals={event("bad_bot_scanner", "bad_bot")}}, "BLOCK_REQUEST", 403, "request")
check("XFF chain abuse: request only", {signals={event("xff_chain_abuse", "xff_guard")}}, "BLOCK_REQUEST", 403, "request")
check("XFF spoof alone: observe", {signals={event("xff_spoof", "xff_guard")}}, "OBSERVE", nil, "request")
check("geo policy: request denied", {signals={event("geo_block", "geo_block")}}, "BLOCK_REQUEST", 403, "request")
check("rate-only: 429", {signals={event("rate_limit_hard", "rate_limit")}}, "THROTTLE", 429, "request")
check("redis rate-only: 429", {signals={event("redis_rate_exceeded", "rate_limit_redis")}}, "THROTTLE", 429, "request")
check("WAF takes priority over rate", {signals={event("rate_limit_hard", "rate_limit"), event("waf_sqli", "waf_sqli_xss")}}, "BLOCK_REQUEST", 403, "request")
check("JWT required missing", {jwt_required=true, jwt_status="missing", signals={event("jwt_missing", "jwt_auth")}}, "BLOCK_REQUEST", 403, "request")
check("JWT valid from changed IP: re-auth only", {jwt_required=true, jwt_status="ip_changed", signals={event("jwt_replay", "jwt_auth")}}, "REAUTH_SESSION", 401, "session")
check("JWT missing signal is fail closed", {jwt_required=true}, "UNAVAILABLE", 503, "request")
check("JWT verified allows route", {jwt_required=true,jwt_status="verified"}, "ALLOW", nil, "request")
check("JWT invalid without signal still denied", {jwt_required=true,jwt_status="invalid"}, "BLOCK_REQUEST", 403, "request")
check("JWT unavailable", {jwt_required=true,jwt_status="error"}, "UNAVAILABLE", 503, "request")
check("account A restricted", {account_restricted=true}, "ACCOUNT_RESTRICT", 429, "account")
check("shared IP account B unaffected", {account_restricted=false}, "ALLOW", nil, "request")
check("manual verified ban", {ip_ban={active=true, verified=true, origin="manual"}}, "DENY_IP", 403, "ip")
check("automatic verified ban", {ip_ban={active=true, verified=true, origin="automatic"}}, "DENY_IP", 403, "ip")
check("high risk alone cannot ban IP", {risk_score=100}, "OBSERVE", nil, "request")
check("ML signal cannot ban IP", {signals={event("ml_anomaly", "ml_detector")}, risk_score=99}, "OBSERVE", nil, "request")
check("infra failure is not malicious evidence", {required_control_failed=true}, "UNAVAILABLE", 503, "request")
check("unknown future signal is observe-only", {signals={event("future_signal", "future_detector")}}, "OBSERVE", nil, "request")
invalid("unverified IP ban is rejected", {ip_ban={active=true,verified=false,origin="automatic"}}, "unverified_ip_ban")
invalid("untrusted detector origin rejected", {signals={event("waf_sqli", "bad_bot")}}, "invalid_signal_source:waf_sqli")
invalid("malformed input rejected", "unsafe", "invalid_input")
invalid("invalid risk score rejected", {risk_score=101}, "invalid_risk_score")

print(string.format("%d security policy contract tests PASS", passed))
