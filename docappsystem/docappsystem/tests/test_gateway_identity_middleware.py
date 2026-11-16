"""Regression tests for Django's GatewayIdentityMiddleware trust boundary.

Run with: python manage.py test docappsystem.tests.test_gateway_identity_middleware
Uses Django SimpleTestCase; no database or external network is required.
"""

import os
import time
from unittest.mock import patch

import jwt
from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase

from docappsystem.middleware import GatewayIdentityMiddleware


class GatewayIdentityMiddlewareTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.secret = os.environ.get("JWT_SECRET_KEY")
        if not self.secret:
            self.fail("JWT_SECRET_KEY must be available in the test environment")

    def _token(self, *, secret=None, **overrides):
        now = int(time.time())
        payload = {
            "user_id": 42,
            "role": "doctor",
            "iat": now,
            "nbf": now - 1,
            "exp": now + 300,
        }
        payload.update(overrides)
        return jwt.encode(payload, secret if secret is not None else self.secret, algorithm="HS256")

    def _request(self, path="/gateway-jwt-probe", **headers):
        seen = []

        def downstream(request):
            seen.append((request.gateway_user_id, request.gateway_user_role))
            return HttpResponse("DOWNSTREAM_REACHED")

        request = self.factory.get(path, **headers)
        response = GatewayIdentityMiddleware(downstream)(request)
        return response, seen

    def test_no_authorization_is_rejected(self):
        response, seen = self._request()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(seen, [])

    def test_forged_identity_headers_without_jwt_are_rejected(self):
        response, seen = self._request(
            HTTP_X_USER_ID="1", HTTP_X_USER_ROLE="admin"
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(seen, [])

    def test_valid_jwt_sets_identity_and_ignores_forged_headers(self):
        response, seen = self._request(
            HTTP_AUTHORIZATION="Bearer " + self._token(),
            HTTP_X_USER_ID="1",
            HTTP_X_USER_ROLE="admin",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(seen, [(42, "doctor")])

    def test_wrong_signature_is_rejected(self):
        response, seen = self._request(
            HTTP_AUTHORIZATION="Bearer " + self._token(secret=self.secret + "-wrong")
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(seen, [])

    def test_expired_jwt_is_rejected(self):
        now = int(time.time())
        response, seen = self._request(
            HTTP_AUTHORIZATION="Bearer " + self._token(iat=now - 100, exp=now - 5)
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(seen, [])

    def test_future_nbf_is_rejected(self):
        response, seen = self._request(
            HTTP_AUTHORIZATION="Bearer " + self._token(nbf=int(time.time()) + 60)
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(seen, [])

    def test_future_iat_is_rejected(self):
        response, seen = self._request(
            HTTP_AUTHORIZATION="Bearer " + self._token(iat=int(time.time()) + 60)
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(seen, [])

    def test_disallowed_algorithm_is_rejected(self):
        token = jwt.encode(
            {"user_id": 42, "role": "doctor", "exp": int(time.time()) + 300},
            key=None,
            algorithm="none",
        )
        response, seen = self._request(HTTP_AUTHORIZATION="Bearer " + token)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(seen, [])

    def test_web_route_ignores_gateway_identity_headers(self):
        response, seen = self._request(
            path="/login/", HTTP_X_USER_ID="1", HTTP_X_USER_ROLE="admin"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(seen, [(None, None)])

    def test_missing_secret_fails_closed(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": ""}):
            response, seen = self._request(
                HTTP_AUTHORIZATION="Bearer " + self._token()
            )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(seen, [])
