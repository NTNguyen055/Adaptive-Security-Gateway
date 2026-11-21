"""real-Redis contract tests, opt-in only (never part of offline suite).

Run only against isolated local Redis DB0:
  ASG_RUN_LIVE_REDIS=1 python manage.py test \
    docappsystem.tests.test_login_accounting --settings=docappsystem.settings_local
Redis keys are HMAC-derived from random TEST-NET addresses and .invalid emails.
Never FLUSHDB or scan-and-delete. Token markers expire via Redis TTL.
"""
import ipaddress
import os
import secrets
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import redis

from docappsystem.login_accounting import AccountingError, LoginAccounting


@unittest.skipUnless(
    os.getenv('ASG_RUN_LIVE_REDIS') == '1',
    'explicit opt-in required for real Redis DB0',
)
class AccountAwareRedisContractTests(unittest.TestCase):
    def setUp(self):
        self.accounting = LoginAccounting(
            max_account_failures=3,
            max_pair_failures=2,
            window=120,
            backoff=5,
            max_active=4,
            reservation_seconds=30,
            spray_window=60,
            spray_threshold=3,
        )
        self.redis = self.accounting.redis
        self.ip = str(ipaddress.IPv6Address(
            int(ipaddress.IPv6Address('2001:db8::')) | secrets.randbits(96)
        ))
        self.other_ip = str(ipaddress.IPv6Address(
            int(ipaddress.IPv6Address('2001:db8::')) | secrets.randbits(96)
        ))
        self.address_suffix = secrets.token_hex(8)
        self.email = f'a3-3-{self.address_suffix}@example.invalid'
        self.owned = set()
        self.tokens = set()
        self.tokens_lock = threading.Lock()
        self.track(self.ip, self.email)

    def track(self, ip, email):
        keys = self.accounting._keys(ip, email, 'unused-token')
        for key in keys:
            if key.startswith('bf:v3:req:'):
                continue
            if key not in self.owned:
                self.assertEqual(self.redis.exists(key), 0,
                                 f'Refusing to touch existing key: {key}')
                self.owned.add(key)

    def tearDown(self):
        if self.owned:
            self.redis.delete(*sorted(self.owned))
        # Request-token markers are isolated and random; clean only those
        # returned to this test, not any arbitrary key prefix.
        if self.tokens:
            self.redis.delete(*(f'bf:v3:req:{t}' for t in self.tokens))

    def admit(self, ip=None, email=None):
        ip = ip or self.ip
        email = email or self.email
        result = self.accounting.admit(ip, email)
        if result.token:
            with self.tokens_lock:
                self.tokens.add(result.token)
        return result

    def finalize(self, admission, outcome='failed', ip=None, email=None):
        return self.accounting.finalize(
            ip or self.ip, email or self.email,
            admission.token, outcome,
        )

    def test_concurrency_bounded_per_account(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.admit(), range(8)))
        self.assertEqual(sum(x.status == 'ADMITTED' for x in results), 4)
        self.assertEqual(sum(x.status == 'SATURATED' for x in results), 4)
        keys = self.accounting._keys(self.ip, self.email, 'unused')
        self.assertEqual(self.redis.zcard(keys[2]), 4)
        self.assertEqual(self.redis.exists(keys[6]), 0)

    def test_failed_counts_pair_backoff_and_no_ip_ban(self):
        keys = self.accounting._keys(self.ip, self.email, 'unused')
        a = self.admit()
        self.assertEqual(self.finalize(a), 'OK:FAILED:1:1')
        b = self.admit()
        self.assertEqual(self.finalize(b), 'OK:FAILED:2:2')
        # Two failures cause a short, bounded pair backoff after one
        # probation attempt; never an automatic IP ban.
        c = self.admit()
        self.assertEqual(c.status, 'ADMITTED')
        self.assertEqual(self.admit().status, 'BACKOFF')
        self.assertTrue(0 < self.redis.ttl(keys[6]) <= 5)
        self.assertEqual(self.finalize(c), 'OK:FAILED:3:3:ACCOUNT_THRESHOLD_NEW')
        self.assertEqual(self.redis.get(keys[0]), '3')
        self.assertEqual(self.redis.get(keys[1]), '3')
        self.assertEqual(self.redis.exists(f'blacklist:{self.ip}'), 0)
        self.assertEqual(self.redis.exists(f'brute_force:lockout:{self.ip}'), 0)
        self.assertEqual(self.redis.exists(f'risk:v1:{self.ip}'), 0)

    def test_one_ip_two_accounts_independent(self):
        second = f'b3-{self.address_suffix}@example.invalid'
        self.track(self.ip, second)
        a = self.admit()
        self.finalize(a)
        b = self.admit(email=second)
        self.assertEqual(b.status, 'ADMITTED')
        self.assertEqual(self.finalize(b, email=second), 'OK:FAILED:1:1')
        self.assertEqual(self.redis.exists(f'blacklist:{self.ip}'), 0)

    def test_one_account_two_sources_share_global_counter(self):
        self.track(self.other_ip, self.email)
        a = self.admit()
        self.finalize(a)
        b = self.admit(ip=self.other_ip)
        self.assertEqual(self.finalize(b, ip=self.other_ip), 'OK:FAILED:2:1')
        self.assertEqual(self.accounting._keys(self.ip, self.email, 'u')[0],
                         self.accounting._keys(self.other_ip, self.email, 'u')[0])
        self.assertNotEqual(self.accounting._keys(self.ip, self.email, 'u')[1],
                            self.accounting._keys(self.other_ip, self.email, 'u')[1])

    def test_source_spray_distinct_accounts_observed(self):
        results = []
        for idx in range(4):
            email = f'b{idx}-{self.address_suffix}@example.invalid'
            self.track(self.ip, email)
            a = self.admit(email=email)
            results.append(a)
            self.finalize(a, email=email)
        self.assertEqual([r.spray_threshold_new for r in results],
                         [False, False, True, False])
        key = self.accounting._keys(self.ip, self.email, 'u')[4]
        self.assertEqual(self.redis.zcard(key), 4)
        self.assertNotIn('@', ' '.join(self.owned))

    def test_success_is_idempotent_and_never_resets_failure_counter(self):
        keys = self.accounting._keys(self.ip, self.email, 'u')
        a = self.admit()
        self.finalize(a)
        b = self.admit()
        self.assertEqual(self.finalize(b, 'success'), 'OK:SUCCESS')
        self.assertEqual(self.finalize(b, 'success'), 'DUPLICATE')
        with self.assertRaises(AccountingError):
            self.finalize(b, 'failed')
        self.assertEqual(self.redis.get(keys[0]), '1')
        self.assertIsNotNone(self.redis.get(keys[7]))

    def test_wrong_identity_cannot_finalize_token(self):
        wrong = f'wrong-{self.address_suffix}@example.invalid'
        self.track(self.ip, wrong)
        a = self.admit()
        with self.assertRaises(AccountingError):
            self.finalize(a, 'success', email=wrong)
        self.assertEqual(self.redis.get(f'bf:v3:req:{a.token}').split(':')[0],
                         'pending')
        self.assertEqual(self.finalize(a, 'failed'), 'OK:FAILED:1:1')

    def test_expired_reservation_must_not_commit_success(self):
        a = self.admit()
        keys = self.accounting._keys(self.ip, self.email, a.token)
        self.redis.zadd(keys[2], {a.token: 1})
        with self.assertRaises(AccountingError):
            self.finalize(a, 'success')
        self.assertIsNone(self.redis.get(keys[7]))

    def test_redis_error_fails_closed(self):
        with patch.object(self.redis, 'eval',
                          side_effect=redis.ConnectionError('simulated')):
            with self.assertRaises(AccountingError):
                self.admit()


if __name__ == '__main__':
    unittest.main()
