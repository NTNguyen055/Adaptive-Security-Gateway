"""P0.2 Login Accounting V2 – integration candidate, not activated.

Suggested project destination: docappsystem/docappsystem/login_accounting.py

Requires redis-py (normally a dependency of django-redis).
Security-critical: callers must fail closed on AccountingError and MUST
finalize success before calling django.contrib.auth.login().

This revision is for testing the admission/finalization state machine.
It does not send Telegram notifications; preserve existing alerting when
integrating.  Do not enable without fault injection and regression tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
import os
import secrets

import redis


class AccountingError(Exception):
    """Storage or protocol could not be verified: do not authenticate."""


ADMIT_SCRIPT = r"""
local lock = redis.call('GET', KEYS[2])
local black = redis.call('GET', KEYS[3])
if lock or black then return 'LOCKED' end

local fail_value = redis.call('GET', KEYS[1])
local failures = tonumber(fail_value or '0')
if not failures or failures < 0 then return 'ERROR:COUNTER' end
if failures >= tonumber(ARGV[1]) then return 'LOCKED' end

-- Redis server time, rather than Django/Gateway clocks.
local now = tonumber(redis.call('TIME')[1])
local active_type = redis.call('TYPE', KEYS[4]).ok
if active_type ~= 'none' and active_type ~= 'zset' then
  return 'ERROR:ACTIVE_TYPE'
end

-- A reservation consumes a slot for an entire failure window.
-- An interrupted request is never silently assumed successful or failed.
redis.call('ZREMRANGEBYSCORE', KEYS[4], '-inf', now)
local active = redis.call('ZCARD', KEYS[4])
if failures + active >= tonumber(ARGV[1]) then return 'SATURATED' end

-- Random request token, created by Django; never reuse client input.
local ok = redis.call('SET', KEYS[5], 'pending', 'NX', 'EX', tonumber(ARGV[3]))
if not ok then return 'REPLAY' end
redis.call('ZADD', KEYS[4], now + tonumber(ARGV[2]), ARGV[4])
redis.call('EXPIRE', KEYS[4], tonumber(ARGV[2]) + 1)
return 'ADMITTED'
"""

FINALIZE_SCRIPT = r"""
local outcome = ARGV[2]
if outcome ~= 'success' and outcome ~= 'failed' then return 'ERROR:OUTCOME' end

local state = redis.call('GET', KEYS[5])
if state == 'done:' .. outcome then return 'DUPLICATE' end
if state and string.sub(state, 1, 5) == 'done:' then return 'CONFLICT' end

-- An uncertain finalization must not be retried blindly.
if state and string.sub(state, 1, 11) == 'processing:' then
  return 'INDETERMINATE'
end
if state ~= 'pending' then return 'UNKNOWN' end

local active_type = redis.call('TYPE', KEYS[4]).ok
if active_type ~= 'zset' then return 'EXPIRED' end

local score = tonumber(redis.call('ZSCORE', KEYS[4], ARGV[1]) or '')
local now = tonumber(redis.call('TIME')[1])
if not score or score <= now then return 'EXPIRED' end

local failures = tonumber(redis.call('GET', KEYS[1]) or '0')
if not failures or failures < 0 then return 'ERROR:COUNTER' end

local history = ''
local risk = 0

if outcome == 'failed' then
  history = redis.call('GET', KEYS[6]) or ''
  risk = tonumber(redis.call('GET', KEYS[7]) or '0')
  if not risk then return 'ERROR:RISK' end
end

-- Validate key types BEFORE any write.
-- Redis Lua does not automatically roll back partial writes.
local function valid_type(key, desired)
  local t = redis.call('TYPE', key).ok
  return t == 'none' or t == desired
end

if not valid_type(KEYS[1], 'string') or
   not valid_type(KEYS[2], 'string') or
   not valid_type(KEYS[3], 'string') or
   not valid_type(KEYS[5], 'string') or
   not valid_type(KEYS[6], 'string') or
   not valid_type(KEYS[7], 'string') or
   not valid_type(KEYS[8], 'string') then
  return 'ERROR:TYPE'
end

-- Mark the request as indeterminate before performing writes.
-- Never claim the request has finished prematurely.
local claimed = redis.call(
  'SET',
  KEYS[5],
  'processing:' .. outcome,
  'XX',
  'EX',
  tonumber(ARGV[6])
)

if not claimed then return 'ERROR:CLAIM' end

local result = 'OK:SUCCESS'

if outcome == 'success' then
  -- Successful login does not reset failed attempts.
  redis.call(
    'SET',
    KEYS[8],
    tostring(now),
    'EX',
    tonumber(ARGV[3])
  )
else
  local count = redis.call('INCR', KEYS[1])

  if count == 1 or redis.call('TTL', KEYS[1]) < 0 then
    redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))
  end

  local entry = tostring(now) .. ':' .. tostring(count)
  local entries = {entry}

  for v in string.gmatch(history, '([^,]+)') do
    if #entries >= 10 then break end
    entries[#entries + 1] = v
  end

  redis.call(
    'SET',
    KEYS[6],
    table.concat(entries, ','),
    'EX',
    86400
  )

  if count >= tonumber(ARGV[4]) then
    local cooldown = tonumber(ARGV[5])

    redis.call('EXPIRE', KEYS[1], cooldown)
    redis.call('SET', KEYS[2], '1', 'EX', cooldown)
    redis.call('SET', KEYS[3], '1', 'EX', cooldown)

    if count == tonumber(ARGV[4]) then
      local new_risk = math.min(
        risk + tonumber(ARGV[7]),
        100
      )

      local risk_ttl = 86400
      if new_risk >= 80 then
        risk_ttl = 31536000
      end

      redis.call(
        'SET',
        KEYS[7],
        string.format('%.2f', new_risk),
        'EX',
        risk_ttl
      )

      result = 'OK:LOCKED_NEW:' .. tostring(count)
    else
      result = 'OK:LOCKED:' .. tostring(count)
    end
  else
    result = 'OK:FAILED:' .. tostring(count)
  end
end

-- Release reservation after security-state writes.
redis.call('ZREM', KEYS[4], ARGV[1])

-- Commit marker LAST.
redis.call(
  'SET',
  KEYS[5],
  'done:' .. outcome,
  'EX',
  tonumber(ARGV[6])
)

return result
"""

@dataclass(frozen=True)
class Admission:
    status: str
    token: str | None = None


class LoginAccounting:
    """State machine against Redis DB 0; one key namespace per canonical IP."""

    def __init__(
        self,
        redis_url: str | None = None,
        max_attempts: int | None = None,
        window: int | None = None,
        cooldown: int | None = None,
        risk_penalty: float | None = None,
    ):
        url = redis_url or os.getenv('LOGIN_ACCOUNTING_REDIS_URL', 'redis://redis:6379/0')
        self.redis = redis.Redis.from_url(
            url, decode_responses=True,
            socket_connect_timeout=0.25, socket_timeout=1.0,
            retry_on_timeout=False,
        )
        if self.redis.connection_pool.connection_kwargs.get('db', 0) != 0:
            raise ValueError('Login Accounting must use Redis DB 0')
        self.max_attempts = int(max_attempts or os.getenv('BRUTE_FORCE_MAX_ATTEMPTS', 5))
        self.window = int(window or os.getenv('BRUTE_FORCE_WINDOW', 300))
        self.cooldown = int(cooldown or os.getenv('BRUTE_FORCE_COOLDOWN', 3600))
        self.risk_penalty = float(risk_penalty or os.getenv('BRUTE_FORCE_RISK_PENALTY', 80))
        if self.max_attempts < 1 or self.window < 1 or self.cooldown < 1:
            raise ValueError('Invalid login accounting security settings')
        self.pending_ttl = self.window + 60
        self.done_ttl = max(120, self.window)

    def _keys(self, ip: str, token: str) -> list[str]:
        return [
            f'brute_force:fail:{ip}',
            f'brute_force:lockout:{ip}',
            f'blacklist:{ip}',
            f'bf:v2:active:{ip}',
            f'bf:v2:req:{token}',
            f'brute_force:history:{ip}',
            f'risk:v1:{ip}',
            f'brute_force:success:{ip}',
        ]

    @staticmethod
    def _canonical_ip(ip: str) -> str:
        return str(ip_address(ip))

    def admit(self, client_ip: str) -> Admission:
        try:
            ip = self._canonical_ip(client_ip)
            token = secrets.token_hex(16)
            keys = self._keys(ip, token)
            result = self.redis.eval(
                ADMIT_SCRIPT, 5, *keys[:5],
                self.max_attempts, self.window, self.pending_ttl, token,
            )
        except (redis.RedisError, ValueError, TypeError) as exc:
            raise AccountingError('Admission state unavailable') from exc
        if result == 'ADMITTED':
            return Admission('ADMITTED', token)
        if result in ('LOCKED', 'SATURATED'):
            return Admission(result)
        raise AccountingError(f'Unexpected admission result: {result}')

    def finalize(self, client_ip: str, token: str, outcome: str) -> str:
        if outcome not in ('success', 'failed'):
            raise ValueError('Invalid outcome')
        if not isinstance(token, str) or len(token) != 32 or not all(c in '0123456789abcdef' for c in token):
            raise ValueError('Invalid token')
        try:
            ip = self._canonical_ip(client_ip)
            result = self.redis.eval(
                FINALIZE_SCRIPT, 8, *self._keys(ip, token),
                token, outcome, self.window, self.max_attempts,
                self.cooldown, self.done_ttl, self.risk_penalty,
            )
        except (redis.RedisError, ValueError, TypeError) as exc:
            raise AccountingError('Finalization state unavailable') from exc
        if result == 'DUPLICATE' or result.startswith('OK:'):
            return result
        raise AccountingError(f'Finalization not confirmed: {result}')
