"""Alert-parity tests: only a newly committed lockout creates alert signal.

Place in docappsystem/docappsystem/tests/test_login_accounting_alert.py.
Mocks accounting, never sends Telegram, never touches real security keys.
"""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from docappsystem.login_accounting import Admission


@override_settings(LOGIN_ACCOUNTING_ENABLED=True)
class LoginAccountingAlertTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user(
            username="p02_alert_test_user",
            email="p02_alert_test@example.test",
            password="P02TestPassword#2026",
            user_type="1",
        )

    def post_wrong_password(self):
        return self.client.post(
            reverse("doLogin"),
            {"email": self.user.email, "password": "wrong-password"},
            HTTP_X_REAL_IP="198.51.100.38",
        )

    @patch("docappsystem.views.LoginAccounting")
    def test_newly_committed_lockout_emits_internal_alert(self, mock_cls):
        instance = mock_cls.return_value
        instance.admit.return_value = Admission("ADMITTED", "f" * 32)
        instance.finalize.return_value = "OK:LOCKED_NEW:5"
        response = self.post_wrong_password()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["X-Login-Status"], "failed")
        self.assertEqual(response["X-Login-Accounting"], "sync-v2")
        self.assertEqual(response["X-Login-Alert"], "brute_force_lockout")
        self.assertNotIn("_auth_user_id", self.client.session)
        instance.finalize.assert_called_once_with(
            "198.51.100.38", "f" * 32, "failed"
        )

    @patch("docappsystem.views.LoginAccounting")
    def test_normal_failed_or_existing_lockout_does_not_emit_alert(self, mock_cls):
        instance = mock_cls.return_value
        instance.admit.return_value = Admission("ADMITTED", "a" * 32)
        for outcome in ("OK:FAILED:1", "OK:FAILED:4", "OK:LOCKED:6"):
            with self.subTest(outcome=outcome):
                instance.finalize.return_value = outcome
                response = self.post_wrong_password()
                self.assertEqual(response.status_code, 302)
                self.assertNotIn("X-Login-Alert", response)
                self.assertEqual(response["X-Login-Accounting"], "sync-v2")
