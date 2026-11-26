"""Django account-aware login tests (mock accounting; no Redis DB0)."""
from unittest.mock import patch

from django.contrib.auth import get_user_model, login as django_login
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from docappsystem.login_accounting import AccountingError, Admission, LoginAccounting


@override_settings(LOGIN_ACCOUNTING_ENABLED=True)
class LoginAccountingViewTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user(
            username='a33_accounting_admin',
            email='a33_accounting_admin@example.test',
            password='StrongTestPassword#2026',
            user_type='1',
        )

    def setUp(self):
        self.url = reverse('doLogin')
        self.ip = '198.51.100.27'
        self.token = 'a' * 32

    def post(self, email=None, password='WrongPassword#2026', **kwargs):
        return self.client.post(
            self.url,
            {'email': email or self.user.email, 'password': password},
            HTTP_X_REAL_IP=self.ip,
            **kwargs,
        )

    @patch('docappsystem.views.LoginAccounting')
    def test_success_finalized_before_django_session_created(self, mock_cls):
        accounting = mock_cls.return_value
        accounting.admit.return_value = Admission('ADMITTED', self.token)
        accounting.finalize.return_value = 'OK:SUCCESS'

        def checked_login(request, user):
            accounting.finalize.assert_called_once_with(
                self.ip, self.user.email, self.token, 'success')
            return django_login(request, user)

        with patch('docappsystem.views.login', side_effect=checked_login):
            response = self.post(password='StrongTestPassword#2026')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['X-Login-Status'], 'success')
        self.assertEqual(response['X-Login-Accounting'], 'sync-v3')
        self.assertEqual(self.client.session['_auth_user_id'], str(self.user.pk))
        accounting.admit.assert_called_once_with(self.ip, self.user.email)

    @patch('docappsystem.views.LoginAccounting')
    def test_failed_login_finalizes_by_account_and_has_no_session(self, mock_cls):
        accounting = mock_cls.return_value
        accounting.admit.return_value = Admission('ADMITTED', self.token)
        accounting.finalize.return_value = 'OK:FAILED:1:1'
        response = self.post()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['X-Login-Status'], 'failed')
        self.assertEqual(response['X-Login-Accounting'], 'sync-v3')
        self.assertNotIn('_auth_user_id', self.client.session)
        accounting.finalize.assert_called_once_with(
            self.ip, self.user.email, self.token, 'failed')

    @patch('docappsystem.views.EmailBackEnd.authenticate')
    @patch('docappsystem.views.LoginAccounting')
    def test_backoff_and_saturation_skip_password_check(self, mock_cls, auth):
        for status in ('BACKOFF', 'SATURATED'):
            with self.subTest(status=status):
                accounting = mock_cls.return_value
                accounting.admit.return_value = Admission(status)
                response = self.post(password='StrongTestPassword#2026')
                self.assertEqual(response.status_code, 429)
                self.assertNotIn('X-Login-Status', response)
                self.assertNotIn('X-Login-Accounting', response)
                auth.assert_not_called()
                accounting.finalize.assert_not_called()

    @patch('docappsystem.views.LoginAccounting')
    def test_admission_storage_failure_does_not_authenticate(self, mock_cls):
        mock_cls.return_value.admit.side_effect = AccountingError('Redis down')
        response = self.post(password='StrongTestPassword#2026')
        self.assertEqual(response.status_code, 503)
        self.assertNotIn('_auth_user_id', self.client.session)
        self.assertNotIn('X-Login-Status', response)

    @patch('docappsystem.views.LoginAccounting')
    def test_finalization_storage_failure_never_creates_session(self, mock_cls):
        accounting = mock_cls.return_value
        accounting.admit.return_value = Admission('ADMITTED', self.token)
        accounting.finalize.side_effect = AccountingError('unknown commit')
        response = self.post(password='StrongTestPassword#2026')
        self.assertEqual(response.status_code, 503)
        self.assertNotIn('_auth_user_id', self.client.session)
        accounting.finalize.assert_called_once_with(
            self.ip, self.user.email, self.token, 'success')

    @patch('docappsystem.views.LoginAccounting')
    def test_duplicate_success_finalization_does_not_create_session(self, mock_cls):
        accounting = mock_cls.return_value
        accounting.admit.return_value = Admission('ADMITTED', self.token)
        accounting.finalize.return_value = 'DUPLICATE'
        response = self.post(password='StrongTestPassword#2026')
        self.assertEqual(response.status_code, 503)
        self.assertNotIn('_auth_user_id', self.client.session)

    @patch('docappsystem.views.LoginAccounting')
    def test_missing_gateway_ip_fails_closed(self, mock_cls):
        response = self.client.post(
            self.url,
            {'email': self.user.email, 'password': 'StrongTestPassword#2026'},
        )
        self.assertEqual(response.status_code, 503)
        self.assertNotIn('_auth_user_id', self.client.session)
        mock_cls.assert_not_called()

    @patch('docappsystem.views.LoginAccounting')
    def test_csrf_rejection_does_not_admit(self, mock_cls):
        csrf_client = Client(enforce_csrf_checks=True)
        response = csrf_client.post(
            self.url,
            {'email': self.user.email, 'password': 'wrong'},
            HTTP_X_REAL_IP=self.ip,
        )
        self.assertEqual(response.status_code, 403)
        mock_cls.assert_not_called()

    @override_settings(LOGIN_ACCOUNTING_ENABLED=False)
    @patch('docappsystem.views.LoginAccounting')
    def test_flag_off_preserves_legacy(self, mock_cls):
        response = self.post()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['X-Login-Status'], 'failed')
        self.assertNotIn('X-Login-Accounting', response)
        mock_cls.assert_not_called()

    @patch('docappsystem.views.LoginAccounting')
    def test_invalid_identifier_rejected_before_auth(self, mock_cls):
        response = self.client.post(
            self.url,
            {'email': 'x' * 500, 'password': 'wrong'},
            HTTP_X_REAL_IP=self.ip,
        )
        self.assertEqual(response.status_code, 400)
        mock_cls.assert_not_called()


class AccountingKeyDerivationTests(SimpleTestCase):
    def accounting(self):
        with patch('docappsystem.login_accounting.redis.Redis.from_url') as connect:
            connect.return_value.connection_pool.connection_kwargs = {'db': 0}
            return LoginAccounting()

    def test_hmac_keys_hide_raw_email_and_ip(self):
        accounting = self.accounting()
        first = accounting._keys('198.51.100.10', 'USER@Example.TEST', 'abc')
        normalized = accounting._keys('198.51.100.10', 'user@example.test', 'abc')
        other_ip = accounting._keys('198.51.100.11', 'user@example.test', 'abc')
        self.assertEqual(first, normalized)
        self.assertEqual(first[0], other_ip[0])
        self.assertNotEqual(first[1], other_ip[1])
        self.assertFalse(any('user@' in k for k in first))
        self.assertFalse(any('198.51.100.' in k for k in first))
        self.assertTrue(all(k.startswith('bf:v3:') for k in first))

    def test_invalid_account_identifier_refused(self):
        accounting = self.accounting()
        for identifier in ('', '  ', 'x' * 255, None):
            with self.subTest(identifier=identifier):
                with self.assertRaises(ValueError):
                    accounting._keys('198.51.100.10', identifier, 'abc')

    def test_accounting_rejects_wrong_redis_db(self):
        with patch('docappsystem.login_accounting.redis.Redis.from_url') as connect:
            connect.return_value.connection_pool.connection_kwargs = {'db': 1}
            with self.assertRaises(ValueError):
                LoginAccounting()
