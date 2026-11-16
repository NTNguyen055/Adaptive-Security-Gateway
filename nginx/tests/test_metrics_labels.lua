-- Standalone LuaJIT regression tests; no running Redis/Prometheus required.
-- Usage: luajit test_metrics_labels.lua /tmp/metrics_labels.lua
local src = arg[1] or "nginx/lua/metrics_labels.lua"
local labels = assert(loadfile(src))()
local passed, failed = 0, 0
local function run(name, fn)
    local ok, err = pcall(fn)
    if ok then passed = passed + 1; print("PASS  " .. name)
    else failed = failed + 1; print("FAIL  " .. name .. ": " .. tostring(err)) end
end
run("block action preserved", function() assert(labels.action("block") == "block") end)
run("limit action preserved", function() assert(labels.action("limit") == "limit") end)
run("unknown action normalized to pass", function()
    assert(labels.action("block:1.2.3.4") == "pass")
    assert(labels.action(nil) == "pass")
end)
run("manual ban outranks contextual signals", function()
    assert(labels.reason({"xff_private_client", "ip_blacklist_manual"}, "block") == "ip_blacklist_manual")
end)
run("WAF attack is preferred over rate limit", function()
    assert(labels.reason({"rate_limit_hard", "waf_sqli:union"}, "block") == "waf_sqli")
end)
run("dynamic signal suffix is removed", function()
    assert(labels.reason({"bad_bot_scanner:sqlmap:unique-ip"}, "block") == "bad_bot_scanner")
end)
run("unknown reason is bounded", function()
    assert(labels.reason({"custom_signal_203.0.113.1"}, "block") == "risk_block")
end)
run("unknown limit is bounded", function()
    assert(labels.reason({"client-specific-opaque"}, "limit") == "risk_limit")
end)
run("missing or malformed signals cannot add label values", function()
    assert(labels.reason(nil, "block") == "risk_block")
    assert(labels.reason({123, {}, ""}, "limit") == "risk_limit")
end)
print(string.format("Metrics labels mock tests: %d passed, %d failed, %d total", passed, failed, passed + failed))
if failed > 0 then os.exit(1) end
