-- Standalone regression tests for nginx/lua/jwt_auth.lua.
-- No Redis, Docker network, Django, or real credentials required.
-- All JWT/crypto, request and ngx.shared operations are mocked.
-- Usage: luajit test_jwt_auth.lua /usr/local/openresty/nginx/lua/jwt_auth.lua

local source_path = (arg and arg[1]) or "nginx/lua/jwt_auth.lua"
local original_getenv = os.getenv
local state = {}

local function fixture(user_id, role, exp, iat, nbf)
    return { valid = true, alg = "HS256", verified = true,
             payload = { user_id = user_id, role = role, exp = exp, iat = iat, nbf = nbf } }
end

local fixtures = {
    ["valid.token.sig"] = fixture(42, "doctor", 1100, 900),
    ["admin.token.sig"] = fixture(7, "admin", 1100, 900),
    ["expired.token.sig"] = fixture(42, "doctor", 999, 900),
    ["future.iat.sig"] = fixture(42, "doctor", 1100, 1006),
    ["future.nbf.sig"] = fixture(42, "doctor", 1100, 900, 1010),
    ["invalid.sig.value"] = {valid = true, alg = "HS256", verified = false},
    ["wrong.alg.token"] = {valid = true, alg = "none", verified = false},
}

local function new_cache()
    local cache = { entries = {} }
    function cache:get(k)
        local item = self.entries[k]
        if item and item.expires > state.now then return item.value end
        return nil
    end
    function cache:set(k, v, ttl)
        self.entries[k] = {value=v, expires=state.now + (ttl or 3600)}
        return true
    end
    function cache:delete(k) self.entries[k] = nil end
    return cache
end

-- Explicitly mock the dependencies: this tests the gateway's decision logic,
-- not real SHA-256 hashing, HMAC cryptography, or real nginx regexes.
package.preload["resty.sha256"] = function()
    local sha = {}
    function sha:new() return setmetatable({}, {__index=self}) end
    function sha:update(s) self.input = s; return true end
    function sha:final() return self.input end
    return sha
end
package.preload["resty.string"] = function()
    return {to_hex = function(s) return s end}
end
package.preload["resty.jwt"] = function()
    return {
        load_jwt = function(_, token)
            state.load_calls = state.load_calls + 1
            local f = fixtures[token]
            if not f then return {valid=false} end
            return {valid=f.valid, header={alg=f.alg}}
        end,
        verify = function(_, secret, token)
            state.verify_calls = state.verify_calls + 1
            local f = fixtures[token]
            if secret ~= "test-secret" or not f or not f.verified then
                return {verified=false, reason="synthetic invalid signature"}
            end
            return {verified=true, payload=f.payload}
        end,
    }
end

os.getenv = function(key)
    if key == "JWT_SECRET_KEY" then return state.secret end
    return original_getenv(key)
end

-- Stable ngx object: jwt_auth.lua captures it in a local at module load time.
ngx = {
    WARN = 4, ERR = 3, INFO = 6,
    var = {}, shared = {}, req = {}, re = {},
    time = function() return state.now end,
    log = function(...) end,
}
function ngx.req.clear_header(name) state.headers[name] = nil end
function ngx.req.set_header(name, value) state.headers[name] = tostring(value) end
function ngx.re.find(uri, pattern, flags)
    local prefixes = {"/static/", "/media/", "/admin/", "/doctor/",
                      "/user/", "/profile/", "/password/"}
    for _, p in ipairs(prefixes) do
        if uri:sub(1, #p) == p then return 1 end
    end
    return nil
end
function ngx.re.match(value, pattern, flags)
    -- Minimal stand-in for the Bearer-token format check used by this module.
    local token = type(value) == "string" and
        value:match("^Bearer%s+([%w_%-]+%.[%w_%-]+%.[%w_%-]+)$")
    return token and {token} or nil
end

local auth = assert(loadfile(source_path))()
local function reset()
    state.now = 1000
    state.secret = "test-secret"
    state.headers = {}
    state.load_calls = 0
    state.verify_calls = 0
    ngx.shared.jwt_cache = new_cache()
end
local function call(token, ip, path, injected_headers)
    state.headers = injected_headers or {}
    ngx.var.uri = path or "/api/jwt-probe/"
    ngx.var.http_authorization = token and ("Bearer " .. token) or nil
    ngx.var.realip_remote_addr = ip or "192.0.2.10"
    ngx.var.remote_addr = ip or "192.0.2.10"
    local ctx = {security={risk=0, signals={}, client_ip=ip or "192.0.2.10"}}
    auth.run(ctx)
    return ctx, state.headers
end
local function ok(value, reason)
    if not value then error(reason or "assertion failed", 2) end
end
local function eq(actual, expected, name)
    if actual ~= expected then
        error((name or "value") .. " expected=" .. tostring(expected) .. " actual=" .. tostring(actual), 2)
    end
end

local tests = {
    {"valid cache miss sets identity", function()
        local ctx, headers = call("valid.token.sig")
        ok(ctx.security.jwt_valid, "valid JWT rejected")
        eq(headers["X-User-ID"], "42", "user header")
        eq(headers["X-User-Role"], "doctor", "role header")
        eq(state.verify_calls, 1, "verify count")
        eq(ngx.shared.jwt_cache:get("valid.token.sig"), 1, "valid-cache flag")
    end},
    {"cache hit preserves role without re-verifying", function()
        call("valid.token.sig")
        local ctx, headers = call("valid.token.sig")
        ok(ctx.security.jwt_from_cache, "cache not used")
        eq(headers["X-User-Role"], "doctor", "cache-hit role")
        eq(headers["X-User-ID"], "42", "cache-hit user")
        eq(state.verify_calls, 1, "verify should be skipped on hit")
    end},
    {"cache hit blocks different IP", function()
        call("valid.token.sig", "192.0.2.10")
        local ctx, headers = call("valid.token.sig", "192.0.2.11")
        ok(ctx.security.block and ctx.security.jwt_replay, "IP replay was accepted")
        eq(headers["X-User-ID"], nil, "user identity must not forward")
        eq(headers["X-User-Role"], nil, "role must not forward")
        eq(state.verify_calls, 1, "cache hit must not reverify")
    end},
    {"partial valid cache falls back to signature verification", function()
        call("valid.token.sig")
        ngx.shared.jwt_cache:delete("jwt_role:valid.token.sig")
        local ctx, headers = call("valid.token.sig")
        ok(ctx.security.jwt_valid and not ctx.security.block)
        eq(headers["X-User-Role"], "doctor", "restored role")
        eq(state.verify_calls, 2, "fallback verification count")
    end},
    {"invalid signature is denied and negative-cached", function()
        local ctx, headers = call("invalid.sig.value")
        ok(ctx.security.block and ctx.security.jwt_invalid)
        eq(ngx.shared.jwt_cache:get("invalid.sig.value"), 2, "negative-cache flag")
        local ctx2 = call("invalid.sig.value")
        ok(ctx2.security.block, "negative-cache bypass")
        eq(state.verify_calls, 1, "invalid JWT should not reverify")
    end},
    {"expired token is rejected and not cached as valid", function()
        local ctx, headers = call("expired.token.sig")
        ok(ctx.security.block and ctx.security.jwt_expired)
        eq(ngx.shared.jwt_cache:get("expired.token.sig"), nil, "expired-cache flag")
        eq(headers["X-User-ID"], nil, "expired identity")
    end},
    {"future nbf token is rejected", function()
        local ctx = call("future.nbf.sig")
        ok(ctx.security.block and ctx.security.jwt_nbf)
        eq(ngx.shared.jwt_cache:get("future.nbf.sig"), nil, "nbf-cache flag")
    end},
    {"future iat token must never populate valid cache", function()
        local ctx, headers = call("future.iat.sig")
        ok(ctx.security.block and ctx.security.jwt_iat_future)
        eq(ngx.shared.jwt_cache:get("future.iat.sig"), nil, "iat-cache flag")
        eq(headers["X-User-ID"], nil, "iat identity")
    end},
    {"missing secret denies protected route", function()
        state.secret = nil
        local ctx, headers = call("valid.token.sig", nil, nil,
                                 {["X-User-ID"]="1", ["X-User-Role"]="admin"})
        ok(ctx.security.block and ctx.security.jwt_config_error)
        eq(headers["X-User-ID"], nil, "spoofed ID")
        eq(headers["X-User-Role"], nil, "spoofed role")
    end},
    {"public route clears client-supplied identity", function()
        local ctx, headers = call(nil, nil, "/health/",
                                 {["X-User-ID"]="1", ["X-User-Role"]="admin"})
        ok(ctx.security.jwt_public_path)
        eq(headers["X-User-ID"], nil, "public spoofed ID")
        eq(headers["X-User-Role"], nil, "public spoofed role")
    end},
    {"missing bearer denies forged identity", function()
        local ctx, headers = call(nil, nil, nil,
                                 {["X-User-ID"]="1", ["X-User-Role"]="admin"})
        ok(ctx.security.block and ctx.security.jwt_missing)
        eq(headers["X-User-ID"], nil, "protected spoofed ID")
        eq(headers["X-User-Role"], nil, "protected spoofed role")
    end},
    {"disallowed alg is rejected", function()
        local ctx = call("wrong.alg.token")
        ok(ctx.security.block and ctx.security.jwt_alg_attack)
        eq(state.verify_calls, 0, "should reject before verification")
    end},
}

local passed = 0
local failed = 0
for _, item in ipairs(tests) do
    reset()
    local success, err = pcall(item[2])
    if success then
        passed = passed + 1
        print("PASS  " .. item[1])
    else
        failed = failed + 1
        print("FAIL  " .. item[1] .. "\n      " .. tostring(err))
    end
end
os.getenv = original_getenv
print(string.format("JWT security mock tests: %d passed, %d failed, %d total", passed, failed, passed + failed))
if failed > 0 then os.exit(1) end
