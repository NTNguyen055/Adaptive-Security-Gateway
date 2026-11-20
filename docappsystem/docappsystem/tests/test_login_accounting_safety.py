"""P0.2 isolated Redis contract checks for abnormal finalization paths.

Place in: docappsystem/docappsystem/tests/test_login_accounting_safety.py
Run ONLY against local/isolated Redis DB 0, NEVER production.
"""
import ipaddress
import secrets
import unittest

from docappsystem.login_accounting import AccountingError, LoginAccounting


class LoginAccountingSafetyTests(unittest.TestCase):
    def setUp(self):
        self.accounting = LoginAccounting()
        self.redis = self.accounting.redis
        base = int(ipaddress.IPv6Address("2001:db8::"))
        self.ip = str(ipaddress.IPv6Address(base | secrets.randbits(96)))
        self.tokens = []
        self.base_keys = self.accounting._keys(self.ip, "placeholder")
        self.base_keys.pop(4)
        self.assertEqual(self.redis.exists(*self.base_keys), 0)

    def tearDown(self):
        keys = self.base_keys + [f"bf:v2:req:{token}" for token in self.tokens]
        if keys:
            self.redis.delete(*keys)

    def admit(self):
        admission = self.accounting.admit(self.ip)
        self.assertEqual(admission.status, "ADMITTED")
        self.tokens.append(admission.token)
        return admission

    def test_wrong_type_preflight_preserves_pending_state(self):
        a = self.admit()
        self.redis.rpush(f"brute_force:history:{self.ip}", "bad-state")
        with self.assertRaises(AccountingError):
            self.accounting.finalize(self.ip, a.token, "failed")
        self.assertEqual(self.redis.get(f"bf:v2:req:{a.token}"), "pending")
        self.assertIsNotNone(self.redis.zscore(f"bf:v2:active:{self.ip}", a.token))
        self.assertIsNone(self.redis.get(f"brute_force:fail:{self.ip}"))

    def test_runtime_error_keeps_token_indeterminate_and_prevents_replay(self):
        a = self.admit()
        fail_key = f"brute_force:fail:{self.ip}"
        # A string convertible to float, but invalid for Redis INCR.
        # Forces a Redis command error AFTER 'processing' was written.
        self.redis.set(fail_key, "0.5", ex=300)
        with self.assertRaises(AccountingError):
            self.accounting.finalize(self.ip, a.token, "failed")

        self.assertEqual(self.redis.get(f"bf:v2:req:{a.token}"), "processing:failed")
        self.assertIsNotNone(self.redis.zscore(f"bf:v2:active:{self.ip}", a.token))
        self.assertEqual(self.redis.get(fail_key), "0.5")
        self.assertEqual(self.redis.exists(f"brute_force:lockout:{self.ip}"), 0)
        self.assertEqual(self.redis.exists(f"blacklist:{self.ip}"), 0)

        # Replaying must not increment (or silently finalize) an uncertain request.
        with self.assertRaises(AccountingError):
            self.accounting.finalize(self.ip, a.token, "failed")
        self.assertEqual(self.redis.get(fail_key), "0.5")


if __name__ == "__main__":
    unittest.main()
