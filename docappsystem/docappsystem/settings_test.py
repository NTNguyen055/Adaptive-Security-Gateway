"""Isolated local test settings."""

from .settings_local import *

# Tách biệt hoàn toàn với MySQL development.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

# Test không cần kết nối Redis thật.
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}

# Tăng tốc tạo tài khoản giả lập.
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
]