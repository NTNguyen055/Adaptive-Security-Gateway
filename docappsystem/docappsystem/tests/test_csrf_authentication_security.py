"""Regression tests for CSRF, session authentication, and HTTP request security.

The tests verify browser-origin controls, secure cookies, authentication
state changes, allowed HTTP methods, and reverse-proxy host trust.

CSRF enforcement is enabled explicitly because Django's default test client
otherwise bypasses CSRF verification. Tests use an isolated local database;
no production credentials, external services, or live traffic are required.

Run with Django's test runner using docappsystem.settings_test.
"""

import re

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import Client, RequestFactory, TestCase, override_settings
from django.urls import reverse


@override_settings(
    LOGIN_ACCOUNTING_ENABLED=False,
    ALLOWED_HOSTS=["localhost", "127.0.0.1"],
    CSRF_TRUSTED_ORIGINS=["https://localhost"],
)
class CsrfSessionProtectionTests(TestCase):
    """Verify CSRF enforcement and session protection for browser requests."""

    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user(
            username="csrf_test_doctor",
            email="csrf_test_doctor@example.test",
            password="OldStrong#123",
            user_type="2",
            profile_pic="test/avatar.png",
        )

    def setUp(self):
        # Django's ordinary test Client disables CSRF verification by default.
        self.client = Client(enforce_csrf_checks=True)

    def _get(self, path):
        return self.client.get(path, secure=True, HTTP_HOST="localhost")

    def _csrf_token(self, path="/login/"):
        response = self._get(path)
        self.assertEqual(response.status_code, 200)
        match = re.search(
            rb'name=["\']csrfmiddlewaretoken["\']\s+value=["\']([^"\']+)["\']',
            response.content,
        )
        self.assertIsNotNone(match, "Template must render a masked CSRF token")
        return match.group(1).decode("ascii")

    def _post(self, path, data=None, **headers):
        return self.client.post(
            path,
            data or {},
            secure=True,
            HTTP_HOST="localhost",
            **headers,
        )

    def test_login_template_issues_secure_httponly_csrf_cookie(self):
        token = self._csrf_token()
        self.assertGreater(len(token), 32)
        cookie = self.client.cookies[settings.CSRF_COOKIE_NAME]
        self.assertTrue(cookie["secure"])
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"], "Lax")

    def test_session_cookie_secure_httponly_samesite(self):
        # Inspect the session cookie issued by the real login response.
        token = self._csrf_token()

        response = self._post(
            reverse("doLogin"),
            {
                "email": self.user.email,
                "password": "OldStrong#123",
                "csrfmiddlewaretoken": token,
            },
            HTTP_ORIGIN="https://localhost",
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn(settings.SESSION_COOKIE_NAME, response.cookies)

        cookie = response.cookies[settings.SESSION_COOKIE_NAME]
        self.assertTrue(cookie["secure"])
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"], "Lax")

        self.assertEqual(
            self.client.session.get("_auth_user_id"),
            str(self.user.pk),
        )

    def test_login_rejects_invalid_csrf_token(self):
        self._csrf_token()
        response = self._post(
            reverse("doLogin"),
            {"csrfmiddlewaretoken": "0" * 64},
            HTTP_ORIGIN="https://localhost",
        )
        self.assertEqual(response.status_code, 403)

    def test_login_rejects_cross_origin_with_valid_csrf_token(self):
        token = self._csrf_token()
        response = self._post(
            reverse("doLogin"),
            {"csrfmiddlewaretoken": token},
            HTTP_ORIGIN="https://attacker.example",
        )
        self.assertEqual(response.status_code, 403)

    def test_login_rejects_http_origin_on_https_request(self):
        token = self._csrf_token()
        response = self._post(
            reverse("doLogin"),
            {"csrfmiddlewaretoken": token},
            HTTP_ORIGIN="http://localhost",
        )
        self.assertEqual(response.status_code, 403)

    def test_login_rejects_https_post_without_origin_or_referer(self):
        token = self._csrf_token()
        response = self._post(
            reverse("doLogin"),
            {"csrfmiddlewaretoken": token},
        )
        self.assertEqual(response.status_code, 403)

    def test_login_allows_same_origin_with_valid_token(self):
        token = self._csrf_token()
        response = self._post(
            reverse("doLogin"),
            {
                "email": "nonexistent@example.test",
                "password": "Wrong#123",
                "csrfmiddlewaretoken": token,
            },
            HTTP_ORIGIN="https://localhost",
        )
        # Invalid credentials are intentionally used; no session is created.
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_login_allows_same_site_https_referer_without_origin(self):
        token = self._csrf_token()
        response = self._post(
            reverse("doLogin"),
            {
                "email": "nonexistent@example.test",
                "password": "Wrong#123",
                "csrfmiddlewaretoken": token,
            },
            HTTP_REFERER="https://localhost/login/",
        )
        self.assertEqual(response.status_code, 302)

    def test_login_handler_rejects_non_post_methods_with_valid_csrf(self):
        token = self._csrf_token()
        for method in ("PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                response = self.client.generic(
                    method,
                    reverse("doLogin"),
                    secure=True,
                    HTTP_HOST="localhost",
                    HTTP_ORIGIN="https://localhost",
                    HTTP_X_CSRFTOKEN=token,
                )
                self.assertEqual(response.status_code, 405)

    def test_profile_update_requires_csrf_even_when_authenticated(self):
        self.client.force_login(self.user)
        response = self._post(
            reverse("profile_update"),
            {"first_name": "Forged"},
            HTTP_ORIGIN="https://localhost",
        )
        self.assertEqual(response.status_code, 403)
        self.user.refresh_from_db()
        self.assertNotEqual(self.user.first_name, "Forged")

    def test_password_change_requires_csrf_even_when_authenticated(self):
        self.client.force_login(self.user)
        response = self._post(
            reverse("change_password"),
            {
                "old_password": "OldStrong#123",
                "new_password1": "NewStrong#456",
                "new_password2": "NewStrong#456",
            },
            HTTP_ORIGIN="https://localhost",
        )
        self.assertEqual(response.status_code, 403)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("OldStrong#123"))

    def test_public_signup_requires_csrf(self):
        response = self._post(
            reverse("docsignup"),
            {"username": "fake"},
            HTTP_ORIGIN="https://localhost",
        )
        self.assertEqual(response.status_code, 403)

    def test_public_appointment_creation_requires_csrf(self):
        response = self._post(
            reverse("appointment"),
            {"fullname": "Fake appointment"},
            HTTP_ORIGIN="https://localhost",
        )
        self.assertEqual(response.status_code, 403)

    def test_logout_post_requires_csrf(self):
        self.client.force_login(self.user)
        response = self._post(
            reverse("logout"),
            {},
            HTTP_ORIGIN="https://localhost",
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            self.client.session.get("_auth_user_id"), str(self.user.pk)
        )

    def test_logout_post_with_csrf_destroys_session(self):
        self.client.force_login(self.user)
        token = self._csrf_token(reverse("profile"))
        response = self._post(
            reverse("logout"),
            {"csrfmiddlewaretoken": token},
            HTTP_ORIGIN="https://localhost",
        )
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("_auth_user_id", self.client.session)


@override_settings(
    LOGIN_ACCOUNTING_ENABLED=False,
    ALLOWED_HOSTS=["localhost", "127.0.0.1"],
    CSRF_TRUSTED_ORIGINS=["https://localhost"],
)
class AuthenticationRequestPolicyTests(TestCase):
    """Enforce HTTP-method contracts and trusted proxy-host boundaries."""

    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user(
            username="auth_policy_doctor",
            email="auth_policy_doctor@example.test",
            password="OldStrong#123",
            user_type="2",
            profile_pic="test/avatar.png",
        )

    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)

    def _token(self, path="/login/"):
        response = self.client.get(path, secure=True, HTTP_HOST="localhost")
        self.assertEqual(response.status_code, 200)
        match = re.search(
            rb'name=["\']csrfmiddlewaretoken["\']\s+value=["\']([^"\']+)["\']',
            response.content,
        )
        self.assertIsNotNone(match)
        return match.group(1).decode("ascii")

    def _unsafe(self, method, path, token):
        return self.client.generic(
            method,
            path,
            secure=True,
            HTTP_HOST="localhost",
            HTTP_ORIGIN="https://localhost",
            HTTP_X_CSRFTOKEN=token,
        )

    def test_get_logout_does_not_end_session(self):
        # Logout must not change authentication state on a safe GET request.
        self.client.force_login(self.user)
        response = self.client.get(
            reverse("logout"), secure=True, HTTP_HOST="localhost"
        )
        self.assertEqual(response.status_code, 405)
        self.assertEqual(
            self.client.session.get("_auth_user_id"), str(self.user.pk)
        )

    def test_untrusted_forwarded_host_is_not_used(self):
        # An untrusted forwarded host must not override the actual Host header.
        request = RequestFactory().get(
            "/login/",
            secure=True,
            HTTP_HOST="localhost",
            HTTP_X_FORWARDED_HOST="127.0.0.1",
        )
        self.assertEqual(request.get_host(), "localhost")

    def test_appointment_put_is_not_accepted_as_get(self):
        # PUT must not be handled as a form-rendering GET request.
        token = self._token("/userappointment/")
        response = self._unsafe("PUT", reverse("appointment"), token)
        self.assertEqual(response.status_code, 405)

    def test_password_patch_is_not_accepted_as_get(self):
        # PATCH must not be handled as a form-rendering GET request.
        self.client.force_login(self.user)
        token = self._token(reverse("change_password"))
        response = self._unsafe("PATCH", reverse("change_password"), token)
        self.assertEqual(response.status_code, 405)

    def test_login_page_rejects_post(self):
        # Login form rendering must not accept a state-changing POST.
        token = self._token()
        response = self.client.post(
            reverse("login"),
            {"csrfmiddlewaretoken": token},
            secure=True,
            HTTP_HOST="localhost",
            HTTP_ORIGIN="https://localhost",
        )
        self.assertEqual(response.status_code, 405)
