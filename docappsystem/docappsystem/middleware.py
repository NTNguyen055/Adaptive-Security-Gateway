"""
docappsystem/middleware.py

GatewayIdentityMiddleware — Defense in depth layer
Đọc X-User-ID và X-User-Role được forward từ OpenResty jwt_auth.lua
→ Gán vào request để view có thể dùng mà không cần parse JWT lại

Nếu request không đi qua gateway (ví dụ nội bộ Docker network trực tiếp),
middleware này từ chối các route protected thay vì để Django xử lý tùy ý.
"""

import os
import time
import jwt
import logging
from django.http import JsonResponse
from django.shortcuts import redirect

logger = logging.getLogger("dasapp")

# Đồng bộ 100% với danh sách PUBLIC_PATHS của jwt_auth.lua
_PUBLIC_PATHS = frozenset([
    "/",
    "/login/",
    "/doLogin/",
    "/logout/",  
    "/health/",
    "/health",
    "/doctor/signup/",
    "/static/",
    "/media/",
    "/favicon.ico",
    "/userappointment/",         
    "/User_SearchAppointment/",
    "/sys-admin-panel",
])

# Đồng bộ với WEB_PREFIXES_PATTERN của jwt_auth.lua
# Các prefix này sử dụng Session Cookie của Django thay vì JWT
_WEB_PREFIXES = (
    "/userbase/",
    "/sys-admin-panel/",
    "/static/", "/media/", "/admin/",
    "/doctor/", "/doctors/",
    "/user/", "/users/",
    "/patient/", "/patients/",
    "/manage/", "/search/", "/view/", "/update/",
    "/profile/", "/password/", "/base/", "/logout/"
)

#  Whitelist Role hợp lệ để chống Header Injection
_VALID_ROLES = frozenset(["user", "doctor", "admin", "patient", "manager", "nurse"])

def _is_public(path: str) -> bool:
    """Trả về True nếu path là Public hoặc thuộc Giao diện Web (Không ép buộc JWT từ Gateway)."""
    if path in _PUBLIC_PATHS:
        return True
    
    if path.startswith(_WEB_PREFIXES):
        return True
        
    return False
class GatewayIdentityMiddleware:
    """
    Đọc identity headers từ OpenResty gateway.
    Không verify JWT — gateway đã làm điều đó.
    Chỉ parse và gán vào request để views dùng.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Không tin identity headers do client gửi.
        request.gateway_user_id = None
        request.gateway_user_role = None

        # Web routes sử dụng Django Session, không dùng gateway identity.
        if _is_public(request.path):
            return self.get_response(request)

        authorization = request.META.get("HTTP_AUTHORIZATION", "")
        parts = authorization.split()

        if len(parts) != 2 or parts[0].lower() != "bearer":
            return JsonResponse({"error": "Unauthorized"}, status=401)

        secret = os.environ.get("JWT_SECRET_KEY")

        if not secret:
            logger.error("JWT_SECRET_KEY unavailable in Django")
            return JsonResponse(
                {"error": "Authentication service unavailable"},
                status=503,
            )

        try:
            payload = jwt.decode(
                parts[1],
                secret,
                algorithms=["HS256"],
                options={
                    "require": ["exp"],
                    "verify_iat": False,
                },
            )

            user_id = payload.get("user_id")
            role = payload.get("role", "user")
            iat = payload.get("iat")

            if type(user_id) is not int or user_id <= 0:
                raise ValueError("Invalid user_id")

            if not isinstance(role, str) or role not in _VALID_ROLES:
                raise ValueError("Invalid role")

            # Đồng bộ chính sách iat với OpenResty (dung sai 5 giây).
            if iat is not None:
                if type(iat) not in (int, float) or iat > time.time() + 5:
                    raise ValueError("Invalid iat")

        except (jwt.InvalidTokenError, ValueError, TypeError):
            return JsonResponse({"error": "Unauthorized"}, status=401)

        # Chỉ gán danh tính sau khi JWT đã được xác minh.
        request.gateway_user_id = user_id
        request.gateway_user_role = role

        return self.get_response(request)
