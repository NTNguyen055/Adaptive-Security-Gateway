"""Local-only Django settings for the graduation-project development stack.

All production settings stay in settings.py. The safety checks below prevent
this module from being used accidentally against a remote database.
"""

import os

from .settings import *  # noqa: F401,F403 — intentionally extend the existing settings

if os.environ.get("APP_ENV") != "local":
    raise RuntimeError("settings_local.py requires APP_ENV=local")

if DATABASES["default"]["HOST"] not in {"db", "localhost", "127.0.0.1"}:
    raise RuntimeError("Local settings refuse non-local DB_HOST")

if USE_S3:
    raise RuntimeError("Local settings refuse USE_S3=True")

# mysqlclient expects ssl_mode as a connection argument, not ssl={'ssl-mode': ...}.
# Keep TLS enforcement in production; disable it ONLY on the internal lab DB.
DATABASES["default"]["OPTIONS"].pop("ssl", None)
DATABASES["default"]["OPTIONS"]["ssl_mode"] = "DISABLED"

# All authentication cookies remain Secure: open the lab site with HTTPS.
DEBUG = False
