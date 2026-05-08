from pathlib import Path
import os
import logging
from dotenv import load_dotenv
from django.core.exceptions import ImproperlyConfigured  # Thêm import này

# ============================================================
# BASE
# ============================================================
BASE_DIR = Path(__file__).resolve().parent.parent

# ============================================================
# LOAD ENV — chỉ dùng khi dev local (Docker inject env trực tiếp)
# ============================================================
if os.getenv("USE_DOTENV", "False") == "True":
    env_path = BASE_DIR / ".env"
    if env_path.exists():
        load_dotenv(env_path)


def get_env(name, default=None, required=False):
    val = os.getenv(name, default)
    if required and not val:
        raise RuntimeError(
            f"[CONFIG] Required environment variable '{name}' is not set. "
            f"Check /home/ubuntu/appointment-web/.env"
        )
    return val


# ============================================================
# CORE SECURITY
# ============================================================
SECRET_KEY = get_env("SECRET_KEY", required=True)

DEBUG = get_env("DEBUG", "False").lower() in ["true", "1", "yes"]

if DEBUG:
    import warnings
    warnings.warn(
        "\n[WARNING] DEBUG=True is enabled. "
        "NEVER deploy to production with DEBUG=True.",
        stacklevel=2
    )

# ============================================================
# ALLOWED HOSTS (STRICT)
# ============================================================
_allowed_hosts_str = get_env("ALLOWED_HOSTS", required=True)

ALLOWED_HOSTS = [
    h.strip()
    for h in _allowed_hosts_str.split(",")
    if h.strip()
]

# ============================================================
# CSRF / DOMAIN TRUST
# ============================================================
CSRF_TRUSTED_ORIGINS = [f"https://{h}" for h in ALLOWED_HOSTS]

CSRF_COOKIE_SECURE   = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Lax"

# ============================================================
# SESSION SECURITY
# ============================================================
SESSION_COOKIE_SECURE   = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"

# FIX 4: Đọc TTL từ ENV để đảm bảo đồng bộ tuyệt đối với JWT_TTL (Mặc định 3600s)
SESSION_COOKIE_AGE = int(get_env("SESSION_TTL", "3600"))

SESSION_SAVE_EVERY_REQUEST = False

# ============================================================
# PROXY (OPENRESTY)
# ============================================================
USE_X_FORWARDED_HOST    = True
USE_X_FORWARDED_PORT    = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# ============================================================
# SECURITY HEADERS
# ============================================================
SECURE_SSL_REDIRECT              = False  # Nginx đã lo việc Redirect HTTP -> HTTPS
SECURE_HSTS_SECONDS              = 0      # Tắt HSTS của Django
SECURE_CONTENT_TYPE_NOSNIFF      = False  # Tắt Nosniff của Django
SECURE_REFERRER_POLICY           = None   # Tắt Referrer Policy của Django

# ============================================================
# APPLICATION
# ============================================================
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Third-party
    "crispy_forms",
    "crispy_bootstrap5",
    # Local
    "dasapp",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    # FIX 1: WhiteNoiseMiddleware đã bị gỡ khỏi đây và sẽ được chèn động (Dynamic Injection)
    # ở bên dưới, CHỈ KHI hệ thống không sử dụng AWS S3.
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "docappsystem.middleware.GatewayIdentityMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    # "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF      = "docappsystem.urls"
WSGI_APPLICATION  = "docappsystem.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

CRISPY_ALLOWED_TEMPLATE_PACKS = "bootstrap5"
CRISPY_TEMPLATE_PACK          = "bootstrap5"

# ============================================================
# DATABASE (RDS HARDENED)
# ============================================================
DATABASES = {
    "default": {
        "ENGINE":       "django.db.backends.mysql",
        "NAME":         get_env("DB_NAME",     required=True),
        "USER":         get_env("DB_USER",     required=True),
        "PASSWORD":     get_env("DB_PASSWORD", required=True),
        "HOST":         get_env("DB_HOST",     required=True),
        "PORT":         get_env("DB_PORT",     "3306"),
        "CONN_MAX_AGE": 60,
        "OPTIONS": {
            "charset":         "utf8mb4",
            "connect_timeout": 5,
            "ssl": {"ssl-mode": "REQUIRED"},
            "init_command": "SET sql_mode='STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO'",
        },
    }
}

# ============================================================
# PASSWORD VALIDATION
# ============================================================
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 8}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE     = "Asia/Ho_Chi_Minh"
USE_I18N      = True
USE_TZ        = True

# ============================================================
# STATIC & MEDIA
# ============================================================
STATIC_URL  = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
_static_dir = BASE_DIR / "static"

# FIX 2: Bẫy lỗi sớm (Fail-fast) nếu cấu hình thư mục tĩnh bị xung đột
if STATIC_ROOT.resolve() == _static_dir.resolve():
    raise ImproperlyConfigured(
        "STATIC_ROOT and STATICFILES_DIRS cannot point to the same directory. "
        "It will cause infinite loop during 'collectstatic'."
    )

if not _static_dir.exists():
    _static_dir.mkdir(parents=True, exist_ok=True)

STATICFILES_DIRS = [_static_dir]

MEDIA_URL  = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
AUTH_USER_MODEL    = "dasapp.CustomUser"

# ============================================================
# REDIS CACHE
# ============================================================
CACHES = {
    "default": {
        "BACKEND":  "django_redis.cache.RedisCache",
        "LOCATION": get_env("REDIS_URL", "redis://redis:6379/1"),
        "OPTIONS": {
            "CLIENT_CLASS":          "django_redis.client.DefaultClient",
            "SOCKET_CONNECT_TIMEOUT": 5,
            "SOCKET_TIMEOUT":         5,
            "RETRY_ON_TIMEOUT":       True,
            "CONNECTION_POOL_KWARGS": {"max_connections": 20},
        },
        "KEY_PREFIX": "docapp",
    }
}

SESSION_ENGINE      = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS = "default"

# ============================================================
# AWS S3 & STORAGE BACKENDS
# ============================================================
USE_S3 = get_env("USE_S3", "False") == "True"

if USE_S3:
    AWS_STORAGE_BUCKET_NAME = get_env("AWS_STORAGE_BUCKET_NAME", required=True)
    AWS_S3_REGION_NAME      = get_env("AWS_S3_REGION_NAME", "ap-northeast-1")
    AWS_DEFAULT_ACL         = None
    AWS_QUERYSTRING_AUTH    = False
    AWS_S3_FILE_OVERWRITE   = False
    AWS_S3_CUSTOM_DOMAIN    = f"{AWS_STORAGE_BUCKET_NAME}.s3.{AWS_S3_REGION_NAME}.amazonaws.com"
    AWS_S3_OBJECT_PARAMETERS = {"CacheControl": "max-age=86400"}
    AWS_S3_URL_PROTOCOL     = "https:"

    STORAGES = {
        "default":     {"BACKEND": "storages.backends.s3boto3.S3Boto3Storage", "OPTIONS": {"location": "media"}},
        "staticfiles": {"BACKEND": "storages.backends.s3boto3.S3StaticStorage", "OPTIONS": {"location": "static"}},
    }

    STATIC_URL = f"https://{AWS_S3_CUSTOM_DOMAIN}/static/"
    MEDIA_URL  = f"https://{AWS_S3_CUSTOM_DOMAIN}/media/"

else:
    # Môi trường dev (hoặc production không dùng S3)
    STORAGES = {
        "default":     {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
    }
    # FIX 1: Chèn WhiteNoiseMiddleware vào đúng vị trí số 1 (sau SecurityMiddleware)
    MIDDLEWARE.insert(1, "whitenoise.middleware.WhiteNoiseMiddleware")

# ============================================================
# LOGGING
# ============================================================
_log_level = "DEBUG" if DEBUG else "INFO"

LOGGING = {
    "version":                  1,
    "disable_existing_loggers": False,
    "formatters": {
        "console": {
            "format": "[%(asctime)s] %(levelname)-8s %(name)s: %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        # FIX 3: Sửa %(message)r thành "%(message)s" bên trong ngoặc kép
        # Đảm bảo các hệ thống đọc Log tập trung (ELK, Datadog...) không bị gãy format JSON
        "json": {
            "()":      "logging.Formatter",
            "format":  '{"time":"%(asctime)s","level":"%(levelname)s",'
                       '"logger":"%(name)s","msg":"%(message)s"}',
            "datefmt": "%Y-%m-%dT%H:%M:%S",
        },
    },
    "filters": {
        "require_debug_false": {"()": "django.utils.log.RequireDebugFalse"},
        "require_debug_true":  {"()": "django.utils.log.RequireDebugTrue"},
    },
    "handlers": {
        "console": {
            "class":     "logging.StreamHandler",
            "formatter": "console",
        },
    },
    "loggers": {
        "django":             {"handlers": ["console"], "level": _log_level, "propagate": False},
        "django.db.backends": {"handlers": ["console"], "level": "DEBUG" if DEBUG else "WARNING", "propagate": False},
        "django.security":    {"handlers": ["console"], "level": "WARNING", "propagate": False},
        "dasapp":             {"handlers": ["console"], "level": _log_level, "propagate": False},
    },
    "root": {
        "handlers": ["console"],
        "level":    _log_level,
    },
}