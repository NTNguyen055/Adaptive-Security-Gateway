"""P0.2 local Redis contract tests (real Redis DB 0, isolated synthetic IP).

Suggested destination:
  docappsystem/docappsystem/tests/test_login_accounting.py
Run inside an ephemeral Django application container after building the app image.
Only exact keys of this test's randomly generated documentation IP are removed.
"""

import ipaddress
import secrets
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import redis

from docappsystem.login_accounting import AccountingError, LoginAccounting


class LoginAccountingRedisContractTests(unittest.TestCase):
    def setUp(self):
        self.accounting = LoginAccounting()
        prefix = int(ipaddress.IPv6Address('2001:db8::'))
        self.ip = str(ipaddress.IPv6Address(prefix | secrets.randbits(96)))
        self.tokens = set()
        self.redis = self.accounting.redis
        self.base_keys = self.accounting._keys(self.ip, 'placeholder')
        self.base_keys.pop(4)
        self.assertEqual(self.redis.exists(*self.base_keys), 0, 'Isolated IP already has state')

    def tearDown(self):
        keys = self.base_keys + [f'bf:v2:req:{t}' for t in self.tokens]
        if keys:
            self.redis.delete(*keys)

    def admit(self):
        result = self.accounting.admit(self.ip)
        if result.token:
            self.tokens.add(result.token)
        return result

    def test_eight_concurrent_requests_cannot_exceed_budget(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.admit(), range(8)))
        admitted = [r for r in results if r.status == 'ADMITTED']
        saturated = [r for r in results if r.status == 'SATURATED']
        self.assertEqual(len(admitted), 5)
        self.assertEqual(len(saturated), 3)
        self.assertEqual(self.redis.zcard(f'bf:v2:active:{self.ip}'), 5)

    def test_success_and_failure_then_lockout_idempotently(self):
        admitted = [self.admit() for _ in range(5)]
        self.assertTrue(all(a.status == 'ADMITTED' for a in admitted))
        a0 = admitted[0]
        self.assertEqual(self.accounting.finalize(self.ip, a0.token, 'success'), 'OK:SUCCESS')
        self.assertEqual(self.accounting.finalize(self.ip, a0.token, 'success'), 'DUPLICATE')

        for idx, a in enumerate(admitted[1:], start=1):
            self.assertEqual(self.accounting.finalize(self.ip, a.token, 'failed'), f'OK:FAILED:{idx}')

        self.assertEqual(self.redis.get(f'brute_force:fail:{self.ip}'), '4')
        self.assertEqual(self.redis.zcard(f'bf:v2:active:{self.ip}'), 0)
        self.assertEqual(self.redis.exists(f'brute_force:lockout:{self.ip}'), 0)

        last = self.admit()
        self.assertEqual(last.status, 'ADMITTED')
        self.assertEqual(self.accounting.finalize(self.ip, last.token, 'failed'), 'OK:LOCKED_NEW:5')
        self.assertEqual(self.accounting.finalize(self.ip, last.token, 'failed'), 'DUPLICATE')
        with self.assertRaises(AccountingError):
            self.accounting.finalize(self.ip, last.token, 'success')

        self.assertEqual(self.redis.get(f'brute_force:fail:{self.ip}'), '5')
        self.assertEqual(self.redis.get(f'brute_force:lockout:{self.ip}'), '1')
        self.assertEqual(self.redis.get(f'blacklist:{self.ip}'), '1')
        self.assertEqual(self.admit().status, 'LOCKED')
        history = self.redis.get(f'brute_force:history:{self.ip}')
        self.assertEqual(len(history.split(',')), 5)
        self.assertEqual(float(self.redis.get(f'risk:v1:{self.ip}')), 80.0)

    def test_expired_reservation_cannot_finalize_as_success(self):
        a = self.admit()
        self.assertEqual(a.status, 'ADMITTED')
        self.redis.zadd(f'bf:v2:active:{self.ip}', {a.token: 1})
        with self.assertRaises(AccountingError):
            self.accounting.finalize(self.ip, a.token, 'success')
        self.assertIsNone(self.redis.get(f'brute_force:success:{self.ip}'))

    def test_redis_unavailable_fails_closed(self):
        with patch.object(self.redis, 'eval', side_effect=redis.ConnectionError('simulated')):
            with self.assertRaises(AccountingError):
                self.accounting.admit(self.ip)


if __name__ == '__main__':
    unittest.main()
