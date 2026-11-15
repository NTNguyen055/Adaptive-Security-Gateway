"""Regression tests for production RDS TLS and local database settings."""

import os
import subprocess
import sys
from pathlib import Path

from django.test import SimpleTestCase


class DatabaseSettingsTests(SimpleTestCase):
    PROJECT_ROOT = Path(__file__).resolve().parents[2]

    BASE_ENV = {
        "USE_DOTENV": "False",
        "SECRET_KEY": "ci-only-dummy-secret-for-db-tests",
        "JWT_SECRET_KEY": "ci-only-dummy-jwt-secret-for-db-tests",
        "DEBUG": "False",
        "ALLOWED_HOSTS": "localhost",
        "DB_NAME": "unused_test_db",
        "DB_USER": "unused_test_user",
        "DB_PASSWORD": "unused_test_password",
        "DB_HOST": "localhost",
        "DB_PORT": "3306",
        "DB_SSL_CA": "/etc/ssl/certs/rds-global-bundle.pem",
        "REDIS_URL": "redis://localhost:6379/1",
    }

    CHECK_SCRIPT = """
import django
import os
django.setup()

from django.conf import settings

options = settings.DATABASES["default"]["OPTIONS"]

assert options["charset"] == "utf8mb4"
assert options["connect_timeout"] == 5
assert options["init_command"] == (
    "SET sql_mode='STRICT_TRANS_TABLES,NO_ZERO_DATE,"
    "NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO'"
)

if os.environ.get("APP_ENV") == "local":
    assert "ssl" not in options
    assert options["ssl_mode"] == "DISABLED"
    print("LOCAL DATABASE TLS CONFIGURATION: PASS")
else:
    assert options["ssl_mode"] == "VERIFY_IDENTITY"
    assert options["ssl"]["ca"] == (
        "/etc/ssl/certs/rds-global-bundle.pem"
    )
    print("PRODUCTION RDS TLS CONFIGURATION: PASS")
"""

    def run_settings_check(self, local=False):
        env = os.environ.copy()
        env.update(self.BASE_ENV)

        if local:
            env.update({
                "APP_ENV": "local",
                "DJANGO_SETTINGS_MODULE": "docappsystem.settings_local",
            })
        else:
            env.pop("APP_ENV", None)
            env["DJANGO_SETTINGS_MODULE"] = "docappsystem.settings"

        result = subprocess.run(
            [sys.executable, "-c", self.CHECK_SCRIPT],
            cwd=self.PROJECT_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

        self.assertEqual(
            result.returncode,
            0,
            msg=(
                f"Database settings failed (local={local}).\n"
                f"STDOUT:\n{result.stdout}\n"
                f"STDERR:\n{result.stderr}"
            ),
        )

    def test_production_rds_tls_configuration(self):
        self.run_settings_check(local=False)

    def test_local_database_disables_rds_tls(self):
        self.run_settings_check(local=True)
