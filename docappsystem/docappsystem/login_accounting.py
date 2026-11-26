"""NAT-aware, account-aware atomic login accounting.

Feature-flagged OFF by default. Requires gateway-trusted X-Real-IP on /doLogin/.
Passwords and raw email addresses are never placed into Redis keys or logs.

Risk trade-off: backoff/active-admission contention can still temporarily delay a
legitimate user during an ongoing targeted account attack. Without a verified
step-up channel (e.g. MFA), zero attacker-induced account DoS is impossible.
Do not deploy publicly until gateway trust, fault injection and E2E are verified.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from ipaddress import ip_address
import os
import secrets

from django.conf import settings
import redis


class AccountingError(Exception):
    """Could not prove atomic accounting state; fail closed before session."""


# KEYS (same positions for admit and finalize):
# 1 account_fail, 2 account+source pair_fail, 3 active-account ZSET,
# 4 request token, 5 per-source distinct-target ZSET,
# 6 account short-backoff gate, 7 pair short-backoff gate, 8 success marker.
# No legacy blacklist, IP lockout, or IP reputation keys.
ADMIT_SCRIPT = r"""
local function good_type(key, expected)
  local t = redis.call('TYPE', key).ok
  return t == 'none' or t == expected
end
local function count(key)
  local raw = redis.call('GET', key)
  if not raw then return 0 end
  if not string.match(raw, '^%d+$') then return nil end
  local n = tonumber(raw)
  if not n or n < 0 or n > 1000000000 then return nil end
  return n
end
if not good_type(KEYS[1], 'string') or
   not good_type(KEYS[2], 'string') or
   not good_type(KEYS[3], 'zset') or
   not good_type(KEYS[4], 'string') or
   not good_type(KEYS[5], 'zset') or
   not good_type(KEYS[6], 'string') or
   not good_type(KEYS[7], 'string') or
   not good_type(KEYS[8], 'string') then
  return 'ERROR:TYPE'
end
local account_n = count(KEYS[1])
local pair_n = count(KEYS[2])
if not account_n or not pair_n then return 'ERROR:COUNTER' end
if redis.call('EXISTS', KEYS[4]) ~= 0 then return 'REPLAY' end
local account_hot = account_n >= tonumber(ARGV[1])
local pair_hot = pair_n >= tonumber(ARGV[2])
if account_hot and redis.call('EXISTS', KEYS[6]) ~= 0 then
  return 'BACKOFF'
end
if pair_hot and redis.call('EXISTS', KEYS[7]) ~= 0 then
  return 'BACKOFF'
end
local now = tonumber(redis.call('TIME')[1])
redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now)
local active = redis.call('ZCARD', KEYS[3])
if active >= tonumber(ARGV[3]) then return 'SATURATED' end
redis.call('ZREMRANGEBYSCORE', KEYS[5], '-inf', now - tonumber(ARGV[10]))
local was_seen = redis.call('ZSCORE', KEYS[5], ARGV[8])

-- Gates reduce guessing throughput, but never create an account lockout key.
-- One probation request is permitted per bounded backoff period.
if account_hot then
  redis.call('SET', KEYS[6], '1', 'EX', tonumber(ARGV[12]))
end
if pair_hot then
  redis.call('SET', KEYS[7], '1', 'EX', tonumber(ARGV[12]))
end
local binding = 'pending:' .. ARGV[8] .. ':' .. ARGV[9]
local created = redis.call(
  'SET', KEYS[4], binding, 'NX', 'EX', tonumber(ARGV[6]))
if not created then return 'REPLAY' end
redis.call('ZADD', KEYS[3], now + tonumber(ARGV[5]), ARGV[7])
redis.call('EXPIRE', KEYS[3], tonumber(ARGV[5]) + 1)
redis.call('ZADD', KEYS[5], now, ARGV[8])
redis.call('EXPIRE', KEYS[5], tonumber(ARGV[10]) + 1)
local distinct = redis.call('ZCARD', KEYS[5])
if not was_seen and distinct == tonumber(ARGV[11]) then
  return 'ADMITTED:SPRAY_NEW'
end
return 'ADMITTED'
"""

FINALIZE_SCRIPT = r"""
local function good_type(key, expected)
  local t = redis.call('TYPE', key).ok
  return t == 'none' or t == expected
end
local function checked_count(key)
  local raw = redis.call('GET', key)
  if not raw then return 0 end
  if not string.match(raw, '^%d+$') then return nil end
  local n = tonumber(raw)
  if not n or n < 0 or n >= 1000000000 then return nil end
  return n
end
local outcome = ARGV[2]
if outcome ~= 'success' and outcome ~= 'failed' then return 'ERROR:OUTCOME' end
local binding = ARGV[5] .. ':' .. ARGV[6]
local pending = 'pending:' .. binding
local done = 'done:' .. outcome .. ':' .. binding
local state = redis.call('GET', KEYS[4])
if state == done then return 'DUPLICATE' end
if state and string.sub(state, 1, 5) == 'done:' then return 'CONFLICT' end
if state and string.sub(state, 1, 11) == 'processing:' then
  return 'INDETERMINATE'
end
if state ~= pending then return 'UNKNOWN' end
if not good_type(KEYS[1], 'string') or
   not good_type(KEYS[2], 'string') or
   not good_type(KEYS[3], 'zset') or
   not good_type(KEYS[5], 'zset') or
   not good_type(KEYS[6], 'string') or
   not good_type(KEYS[7], 'string') or
   not good_type(KEYS[8], 'string') then
  return 'ERROR:TYPE'
end
local score = tonumber(redis.call('ZSCORE', KEYS[3], ARGV[1]) or '')
local now = tonumber(redis.call('TIME')[1])
if not score or score <= now then return 'EXPIRED' end
local account_n, pair_n = 0, 0
if outcome == 'failed' then
  account_n = checked_count(KEYS[1])
  pair_n = checked_count(KEYS[2])
  if not account_n or not pair_n then return 'ERROR:COUNTER' end
end
local claimed = redis.call('SET', KEYS[4],
  'processing:' .. outcome .. ':' .. binding,
  'XX', 'EX', tonumber(ARGV[4]))
if not claimed then return 'ERROR:CLAIM' end
local result = 'OK:SUCCESS'
if outcome == 'failed' then
  account_n = redis.call('INCR', KEYS[1])
  pair_n = redis.call('INCR', KEYS[2])
  if account_n == 1 or redis.call('TTL', KEYS[1]) < 0 then
    redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))
  end
  if pair_n == 1 or redis.call('TTL', KEYS[2]) < 0 then
    redis.call('EXPIRE', KEYS[2], tonumber(ARGV[3]))
  end
  result = 'OK:FAILED:' .. tostring(account_n) .. ':' .. tostring(pair_n)
  if account_n == tonumber(ARGV[7]) then
    result = result .. ':ACCOUNT_THRESHOLD_NEW'
  end
else
  redis.call('SET', KEYS[8], tostring(now), 'EX', tonumber(ARGV[3]))
end
redis.call('ZREM', KEYS[3], ARGV[1])
redis.call('SET', KEYS[4], done, 'EX', tonumber(ARGV[4]))
return result
"""


@dataclass(frozen=True)
class Admission:
    status: str
    token: str | None = None
    spray_threshold_new: bool = False


class LoginAccounting:
    """Atomic Redis DB0 accounting, with HMAC pseudonymous account keys."""

    def __init__(
        self,
        redis_url: str | None = None,
        max_account_failures: int | None = None,
        max_pair_failures: int | None = None,
        window: int | None = None,
        backoff: int | None = None,
        max_active: int | None = None,
        reservation_seconds: int | None = None,
        spray_window: int | None = None,
        spray_threshold: int | None = None,
    ):
        url = redis_url or os.getenv(
            'LOGIN_ACCOUNTING_REDIS_URL', 'redis://redis:6379/0'
        )
        try:
            self.redis = redis.Redis.from_url(
                url, decode_responses=True,
                socket_connect_timeout=0.25, socket_timeout=1.0,
                retry_on_timeout=False,
            )
        except (redis.RedisError, ValueError) as exc:
            raise AccountingError('Accounting Redis configuration unavailable') from exc
        if self.redis.connection_pool.connection_kwargs.get('db', 0) != 0:
            raise ValueError('Login Accounting must use Redis DB 0')
        def setting(value, name, default):
            result = int(value if value is not None else os.getenv(name, default))
            if result < 1 or result > 86400:
                raise ValueError('Invalid login accounting limit')
            return result

        self.account_limit = setting(
            max_account_failures, 'LOGIN_ACCOUNT_MAX_FAILURES', 12)
        self.pair_limit = setting(
            max_pair_failures, 'LOGIN_PAIR_MAX_FAILURES', 5)
        self.window = setting(window, 'BRUTE_FORCE_WINDOW', 300)
        self.backoff = setting(backoff, 'LOGIN_ACCOUNT_BACKOFF_SECONDS', 10)
        self.max_active = setting(max_active, 'LOGIN_ACCOUNT_MAX_ACTIVE', 4)
        self.reservation_seconds = setting(
            reservation_seconds, 'LOGIN_RESERVATION_SECONDS', 30)
        self.spray_window = setting(
            spray_window, 'LOGIN_SPRAY_WINDOW_SECONDS', 60)
        self.spray_threshold = setting(
            spray_threshold, 'LOGIN_SPRAY_DISTINCT_THRESHOLD', 10)
        self.pending_ttl = self.reservation_seconds + 60
        self.done_ttl = max(120, self.window)

    @staticmethod
    def _canonical_ip(value: str) -> str:
        return str(ip_address(value))

    @staticmethod
    def _canonical_account(email: str) -> str:
        if not isinstance(email, str):
            raise ValueError('Invalid account identifier')
        value = email.strip().casefold()
        if not value or len(value) > 254 or len(value.encode('utf-8')) > 512:
            raise ValueError('Invalid account identifier')
        return value

    @staticmethod
    def _digest(label: str, raw: str) -> str:
        key = settings.SECRET_KEY.encode('utf-8')
        return hmac.new(
            key,
            ('asg:bf:v3:' + label + '\0' + raw).encode('utf-8'),
            hashlib.sha256,
        ).hexdigest()

    def _keys(self, client_ip: str, email: str, token: str) -> list[str]:
        ip = self._canonical_ip(client_ip)
        account = self._canonical_account(email)
        acct_hash = self._digest('account', account)
        source_hash = self._digest('source', ip)
        pair_hash = self._digest('pair', account + '\0' + ip)
        return [
            f'bf:v3:acct_fail:{acct_hash}',
            f'bf:v3:pair_fail:{pair_hash}',
            f'bf:v3:active:{acct_hash}',
            f'bf:v3:req:{token}',
            f'bf:v3:source_targets:{source_hash}',
            f'bf:v3:acct_gate:{acct_hash}',
            f'bf:v3:pair_gate:{pair_hash}',
            f'bf:v3:success:{acct_hash}',
        ]

    def admit(self, client_ip: str, email: str) -> Admission:
        try:
            ip = self._canonical_ip(client_ip)
            account = self._canonical_account(email)
            token = secrets.token_hex(16)
            keys = self._keys(ip, account, token)
            acct_hash = self._digest('account', account)
            pair_hash = self._digest('pair', account + '\0' + ip)
            result = self.redis.eval(
                ADMIT_SCRIPT, 8, *keys,
                self.account_limit, self.pair_limit, self.max_active,
                self.window, self.reservation_seconds, self.pending_ttl,
                token, acct_hash, pair_hash, self.spray_window,
                self.spray_threshold, self.backoff,
            )
        except (redis.RedisError, ValueError, TypeError) as exc:
            raise AccountingError('Admission state unavailable') from exc
        if result in ('ADMITTED', 'ADMITTED:SPRAY_NEW'):
            return Admission(
                'ADMITTED', token, result == 'ADMITTED:SPRAY_NEW'
            )
        if result in ('BACKOFF', 'SATURATED'):
            return Admission(result)
        raise AccountingError(f'Unexpected admission result: {result}')

    def finalize(
        self, client_ip: str, email: str, token: str, outcome: str
    ) -> str:
        if outcome not in ('success', 'failed'):
            raise ValueError('Invalid outcome')
        if (not isinstance(token, str) or len(token) != 32
                or any(c not in '0123456789abcdef' for c in token)):
            raise ValueError('Invalid token')
        try:
            ip = self._canonical_ip(client_ip)
            account = self._canonical_account(email)
            keys = self._keys(ip, account, token)
            acct_hash = self._digest('account', account)
            pair_hash = self._digest('pair', account + '\0' + ip)
            result = self.redis.eval(
                FINALIZE_SCRIPT, 8, *keys,
                token, outcome, self.window, self.done_ttl,
                acct_hash, pair_hash, self.account_limit,
            )
        except (redis.RedisError, ValueError, TypeError) as exc:
            raise AccountingError('Finalization state unavailable') from exc
        if result == 'DUPLICATE' or result.startswith('OK:'):
            return result
        raise AccountingError(f'Finalization not confirmed: {result}')
