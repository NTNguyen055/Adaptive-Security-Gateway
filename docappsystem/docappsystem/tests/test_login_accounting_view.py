"""P0.2 Django login-accounting integration tests (feature flag ON/OFF).

Create in: docappsystem/docappsystem/tests/test_login_accounting_view.py
Mocks Redis accounting only; no production security keys are touched.
"""

from unittest.mock import patch

from django.contrib.auth import get_user_model, login as django_login
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from docappsystem.login_accounting import AccountingError, Admission


@override_settings(LOGIN_ACCOUNTING_ENABLED=True)
class LoginAccountingViewTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user(
            username="p02_accounting_admin",
            email="p02_accounting_admin@example.test",
            password="StrongTestPassword#2026",
            user_type="1",
        )

    def setUp(self):
        self.url = reverse("doLogin")
        self.ip = "198.51.100.27"
        self.token = "a" * 32

    def post(self, password="WrongPassword#2026", **extra):
        return self.client.post(
            self.url,
            {"email": self.user.email, "password": password},
            HTTP_X_REAL_IP=self.ip,
            **extra,
        )

    @patch("docappsystem.views.LoginAccounting")
    def test_success_commits_before_session_and_sets_internal_signal(self, mock_cls):
        accounting = mock_cls.return_value
        accounting.admit.return_value = Admission("ADMITTED", self.token)
        accounting.finalize.return_value = "OK:SUCCESS"

        def checked_login(request, user):
            accounting.finalize.assert_called_once_with(
                self.ip, self.token, "success"
            )
            return django_login(request, user)

        with patch("docappsystem.views.login", side_effect=checked_login):
            response = self.post(password="StrongTestPassword#2026")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["X-Login-Status"], "success")
        self.assertEqual(response["X-Login-Accounting"], "sync-v2")
        self.assertEqual(self.client.session["_auth_user_id"], str(self.user.pk))
        accounting.admit.assert_called_once_with(self.ip)

    @patch("docappsystem.views.LoginAccounting")
    def test_failed_login_is_finalized_once_without_session(self, mock_cls):
        accounting = mock_cls.return_value
        accounting.admit.return_value = Admission("ADMITTED", self.token)
        accounting.finalize.return_value = "OK:FAILED:1"

        response = self.post()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["X-Login-Status"], "failed")
        self.assertEqual(response["X-Login-Accounting"], "sync-v2")
        self.assertNotIn("_auth_user_id", self.client.session)
        accounting.finalize.assert_called_once_with(self.ip, self.token, "failed")

    @patch("docappsystem.views.LoginAccounting")
    def test_redis_admission_error_fails_closed(self, mock_cls):
        accounting = mock_cls.return_value
        accounting.admit.side_effect = AccountingError("simulated Redis outage")

        response = self.post(password="StrongTestPassword#2026")

        self.assertEqual(response.status_code, 503)
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertNotIn("X-Login-Accounting", response)
        self.assertNotIn("X-Login-Status", response)
        accounting.finalize.assert_not_called()

    @patch("docappsystem.views.LoginAccounting")
    def test_redis_finalization_error_does_not_create_session(self, mock_cls):
        accounting = mock_cls.return_value
        accounting.admit.return_value = Admission("ADMITTED", self.token)
        accounting.finalize.side_effect = AccountingError("simulated Redis outage")

        response = self.post(password="StrongTestPassword#2026")

        self.assertEqual(response.status_code, 503)
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertNotIn("X-Login-Accounting", response)
        self.assertNotIn("X-Login-Status", response)
        accounting.finalize.assert_called_once_with(self.ip, self.token, "success")

    @patch("docappsystem.views.LoginAccounting")
    def test_unconfirmed_finalization_does_not_create_session(self, mock_cls):
        accounting = mock_cls.return_value
        accounting.admit.return_value = Admission("ADMITTED", self.token)
        accounting.finalize.return_value = "DUPLICATE"

        response = self.post(password="StrongTestPassword#2026")

        self.assertEqual(response.status_code, 503)
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertNotIn("X-Login-Accounting", response)

    @patch("docappsystem.views.EmailBackEnd.authenticate")
    @patch("docappsystem.views.LoginAccounting")
    def test_locked_or_saturated_skips_password_check(self, mock_cls, mock_auth):
        for status, expected_http in (("LOCKED", 403), ("SATURATED", 429)):
            with self.subTest(status=status):
                accounting = mock_cls.return_value
                accounting.admit.return_value = Admission(status)
                response = self.post(password="StrongTestPassword#2026")
                self.assertEqual(response.status_code, expected_http)
                self.assertNotIn("X-Login-Accounting", response)
                self.assertNotIn("_auth_user_id", self.client.session)
                mock_auth.assert_not_called()
                accounting.finalize.assert_not_called()

    @patch("docappsystem.views.LoginAccounting")
    def test_missing_trusted_ip_fails_closed(self, mock_cls):
        response = self.client.post(
            self.url,
            {"email": self.user.email, "password": "StrongTestPassword#2026"},
        )
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertNotIn("X-Login-Accounting", response)
        mock_cls.assert_not_called()

    @patch("docappsystem.views.LoginAccounting")
    def test_csrf_rejection_does_not_admit(self, mock_cls):
        csrf_client = Client(enforce_csrf_checks=True)
        response = csrf_client.post(
            self.url,
            {"email": self.user.email, "password": "WrongPassword#2026"},
            HTTP_X_REAL_IP=self.ip,
        )
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("X-Login-Accounting", response)
        mock_cls.assert_not_called()

    @override_settings(LOGIN_ACCOUNTING_ENABLED=False)
    @patch("docappsystem.views.LoginAccounting")
    def test_feature_flag_off_preserves_legacy_login(self, mock_cls):
        response = self.post()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["X-Login-Status"], "failed")
        self.assertNotIn("X-Login-Accounting", response)
        mock_cls.assert_not_called()
