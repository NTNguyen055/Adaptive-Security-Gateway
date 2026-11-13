"""Regression tests for local and private S3 media storage."""

import os
import subprocess
import sys
from pathlib import Path

from django.test import SimpleTestCase


class StorageSettingsTests(SimpleTestCase):
    """Verify storage configuration without contacting AWS."""

    PROJECT_ROOT = Path(__file__).resolve().parents[2]

    BASE_ENV = {
        "USE_DOTENV": "False",
        "SECRET_KEY": "ci-only-dummy-secret-for-storage-tests",
        "JWT_SECRET_KEY": "ci-only-dummy-jwt-secret-for-storage-tests",
        "DEBUG": "False",
        "ALLOWED_HOSTS": "localhost",
        "DB_NAME": "unused_storage_test_db",
        "DB_USER": "unused_storage_test_user",
        "DB_PASSWORD": "unused_storage_test_password",
        "DB_HOST": "localhost",
        "DB_PORT": "3306",
        "REDIS_URL": "redis://localhost:6379/1",
        # Prevent boto3 from looking for EC2 instance metadata.
        "AWS_EC2_METADATA_DISABLED": "true",
        # Dummy credentials: configuration tests must never use real keys.
        "AWS_ACCESS_KEY_ID": "testing-only",
        "AWS_SECRET_ACCESS_KEY": "testing-only",
    }

    CHECK_SCRIPT = """
import django
django.setup()

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.storage import storages, FileSystemStorage

assert settings.STORAGES["staticfiles"]["BACKEND"] == (
    "whitenoise.storage.CompressedManifestStaticFilesStorage"
), "Static files must always use WhiteNoise"

assert settings.MIDDLEWARE.count(
    "whitenoise.middleware.WhiteNoiseMiddleware"
) == 1, "WhiteNoise middleware must appear exactly once"

profile_field = get_user_model()._meta.get_field("profile_pic")
assert profile_field.upload_to == "media/profile_pic", (
    "Existing profile picture upload path must remain unchanged"
)

static_storage = storages["staticfiles"]
assert static_storage.__class__.__name__ == (
    "CompressedManifestStaticFilesStorage"
), "Static storage must use WhiteNoise"

if settings.USE_S3:
    from storages.backends.s3boto3 import S3Boto3Storage

    media_storage = storages["default"]

    assert isinstance(media_storage, S3Boto3Storage)
    assert media_storage.bucket_name == "test-media-bucket"
    assert media_storage.location == ""
    assert media_storage.querystring_auth is True
    assert media_storage.querystring_expire == 900

    assert settings.AWS_S3_REGION_NAME == "ap-southeast-1"
    assert settings.AWS_DEFAULT_ACL is None
    assert settings.AWS_S3_SIGNATURE_VERSION == "s3v4"
    assert settings.AWS_S3_USE_SSL is True
    assert settings.AWS_S3_VERIFY is True

    print("S3 PRIVATE MEDIA CONFIGURATION: PASS")
else:
    assert isinstance(storages["default"], FileSystemStorage)
    print("LOCAL MEDIA CONFIGURATION: PASS")
"""

    def run_settings_check(self, use_s3):
        env = os.environ.copy()
        env.update(self.BASE_ENV)
        env.update({
            "DJANGO_SETTINGS_MODULE": "docappsystem.settings",
            "USE_S3": "True" if use_s3 else "False",
        })

        if use_s3:
            env["AWS_STORAGE_BUCKET_NAME"] = "test-media-bucket"
            env["AWS_S3_REGION_NAME"] = "ap-southeast-1"

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
                f"Storage configuration failed (USE_S3={use_s3}).\n"
                f"STDOUT:\n{result.stdout}\n"
                f"STDERR:\n{result.stderr}"
            ),
        )

    def test_local_storage_configuration(self):
        self.run_settings_check(use_s3=False)

    def test_private_s3_media_configuration(self):
        self.run_settings_check(use_s3=True)
