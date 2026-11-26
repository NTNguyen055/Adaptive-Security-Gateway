"""internal attack observation signal tests (no Redis/Telegram)."""
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
            username='a33_alert_test_user',
            email='a33_alert_test@example.test',
            password='P02TestPassword#2026',
            user_type='1',
        )

    def post_wrong_password(self):
        return self.client.post(
            reverse('doLogin'),
            {'email': self.user.email, 'password': 'wrong-password'},
            HTTP_X_REAL_IP='198.51.100.38',
        )

    @patch('docappsystem.views.LoginAccounting')
    def test_new_global_account_threshold_emits_signal(self, mock_cls):
        inst = mock_cls.return_value
        inst.admit.return_value = Admission('ADMITTED', 'f' * 32)
        inst.finalize.return_value = 'OK:FAILED:12:2:ACCOUNT_THRESHOLD_NEW'
        response = self.post_wrong_password()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['X-Login-Accounting'], 'sync-v3')
        self.assertEqual(response['X-Login-Alert'], 'account_guessing')
        self.assertNotIn('_auth_user_id', self.client.session)

    @patch('docappsystem.views.LoginAccounting')
    def test_new_source_spray_threshold_emits_signal(self, mock_cls):
        inst = mock_cls.return_value
        inst.admit.return_value = Admission('ADMITTED', 'e' * 32, True)
        inst.finalize.return_value = 'OK:FAILED:1:1'
        response = self.post_wrong_password()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['X-Login-Alert'], 'password_spraying')

    @patch('docappsystem.views.LoginAccounting')
    def test_regular_failure_does_not_emit_attack_signal(self, mock_cls):
        inst = mock_cls.return_value
        inst.admit.return_value = Admission('ADMITTED', 'a' * 32)
        for outcome in ('OK:FAILED:1:1', 'OK:FAILED:6:3'):
            with self.subTest(outcome=outcome):
                inst.finalize.return_value = outcome
                response = self.post_wrong_password()
                self.assertEqual(response.status_code, 302)
                self.assertNotIn('X-Login-Alert', response)
                self.assertEqual(response['X-Login-Accounting'], 'sync-v3')
