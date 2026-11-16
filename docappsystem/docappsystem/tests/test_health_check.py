from unittest.mock import patch

from django.test import TestCase


class HealthCheckTests(TestCase):

    def test_health_check_returns_200_when_dependencies_are_healthy(self):
        response = self.client.get(
            "/health/",
            HTTP_HOST="localhost",
            HTTP_X_FORWARDED_PROTO="https",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "healthy")
        self.assertEqual(response.json()["checks"]["db"], "ok")
        self.assertEqual(response.json()["checks"]["cache"], "ok")

    def test_health_check_returns_503_when_database_fails(self):
        with patch(
            "docappsystem.urls.transaction.atomic",
            side_effect=RuntimeError("database unavailable"),
        ):
            response = self.client.get(
                "/health/",
                HTTP_HOST="localhost",
                HTTP_X_FORWARDED_PROTO="https",
            )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["status"], "unhealthy")
        self.assertIn("error", response.json()["checks"]["db"])

    def test_health_check_returns_503_when_redis_fails(self):
        with patch(
            "docappsystem.urls.cache.set",
            side_effect=ConnectionError("redis unavailable"),
        ):
            response = self.client.get(
                "/health/",
                HTTP_HOST="localhost",
                HTTP_X_FORWARDED_PROTO="https",
            )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["status"], "unhealthy")
        self.assertIn("error", response.json()["checks"]["cache"])

    def test_health_check_returns_503_when_cache_read_fails(self):
        with patch(
            "docappsystem.urls.cache.get",
            return_value=None,
        ):
            response = self.client.get(
                "/health/",
                HTTP_HOST="localhost",
                HTTP_X_FORWARDED_PROTO="https",
            )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["status"], "unhealthy")
        self.assertEqual(response.json()["checks"]["cache"], "miss")

    def test_health_check_is_exempt_from_gateway_jwt(self):
        response = self.client.get(
            "/health/",
            HTTP_HOST="localhost",
            HTTP_X_FORWARDED_PROTO="https",
        )

        self.assertEqual(response.status_code, 200)
