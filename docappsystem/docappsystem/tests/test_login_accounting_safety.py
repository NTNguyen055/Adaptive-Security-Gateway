"""Redis fault-injection tests; explicit ASG_RUN_LIVE_REDIS=1 only."""
import ipaddress
import os
import secrets
import unittest
from unittest.mock import patch

import redis
from docappsystem.login_accounting import AccountingError, LoginAccounting


@unittest.skipUnless(
    os.getenv('ASG_RUN_LIVE_REDIS') == '1',
    'explicit opt-in required for real Redis DB0',
)
class AccountAwareSafetyTests(unittest.TestCase):
    def setUp(self):
        self.accounting = LoginAccounting(window=120)
        self.redis = self.accounting.redis
        self.ip = str(ipaddress.IPv6Address(
            int(ipaddress.IPv6Address('2001:db8::')) | secrets.randbits(96)
        ))
        self.email = f'safety-{secrets.token_hex(12)}@example.invalid'
        self.keys = self.accounting._keys(self.ip, self.email, 'unused')
        self.assertEqual(self.redis.exists(*self.keys), 0)
        self.tokens = []

    def tearDown(self):
        self.redis.delete(*self.keys)
        if self.tokens:
            self.redis.delete(*(f'bf:v3:req:{t}' for t in self.tokens))

    def admit(self):
        result = self.accounting.admit(self.ip, self.email)
        self.assertEqual(result.status, 'ADMITTED')
        self.tokens.append(result.token)
        return result

    def test_wrong_counter_string_refused_before_any_finalization(self):
        a = self.admit()
        self.redis.set(self.keys[0], '0.5', ex=120)
        with self.assertRaises(AccountingError):
            self.accounting.finalize(self.ip, self.email, a.token, 'failed')
        self.assertTrue(self.redis.get(self.keys[3].replace('unused', a.token))
                        .startswith('pending:'))
        self.assertEqual(self.redis.get(self.keys[0]), '0.5')
        self.assertIsNone(self.redis.get(self.keys[1]))
        self.assertEqual(self.redis.exists(f'blacklist:{self.ip}'), 0)

    def test_wrong_type_rejected_before_pending_token_created(self):
        self.redis.rpush(self.keys[4], 'wrong-type')
        with self.assertRaises(AccountingError):
            self.accounting.admit(self.ip, self.email)
        self.assertIsNone(self.redis.get(self.keys[0]))
        self.assertEqual(self.redis.exists(self.keys[2]), 0)

    def test_ambiguous_response_never_becomes_verified_session(self):
        a = self.admit()
        actual_eval = self.redis.eval

        def commit_then_transport_loss(*args, **kwargs):
            result = actual_eval(*args, **kwargs)
            self.assertEqual(result, 'OK:FAILED:1:1')
            raise redis.ConnectionError('connection lost after commit')

        with patch.object(self.redis, 'eval', side_effect=commit_then_transport_loss):
            with self.assertRaises(AccountingError):
                self.accounting.finalize(self.ip, self.email, a.token, 'failed')
        # A completed marker is durable; retry cannot double-count.
        self.assertEqual(self.accounting.finalize(
            self.ip, self.email, a.token, 'failed'), 'DUPLICATE')
        self.assertEqual(self.redis.get(self.keys[0]), '1')
        self.assertEqual(self.redis.get(self.keys[1]), '1')


if __name__ == '__main__':
    unittest.main()
