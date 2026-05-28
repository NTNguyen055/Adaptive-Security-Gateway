"""
docappsystem/middleware.py

GatewayIdentityMiddleware — Defense in depth layer
Đọc X-User-ID và X-User-Role được forward từ OpenResty jwt_auth.lua
→ Gán vào request để view có thể dùng mà không cần parse JWT lại

Nếu request không đi qua gateway (ví dụ nội bộ Docker network trực tiếp),
middleware này từ chối các route protected thay vì để Django xử lý tùy ý.
"""

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
])

# Đồng bộ với WEB_PREFIXES_PATTERN của jwt_auth.lua
# Các prefix này sử dụng Session Cookie của Django thay vì JWT
_WEB_PREFIXES = (
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
        # Lấy identity từ header được gateway inject
        user_id_str = request.META.get("HTTP_X_USER_ID", "").strip()
        user_role   = request.META.get("HTTP_X_USER_ROLE", "user").strip()

        # Sanitize Role: Nếu Role không có trong danh sách cho phép, ép về "user"
        if user_role not in _VALID_ROLES:
            user_role = "user"

        if user_id_str:
            try:
                request.gateway_user_id   = int(user_id_str)
                request.gateway_user_role = user_role
            except (ValueError, TypeError):
                logger.warning(
                    "GatewayIdentity: invalid X-User-ID header value='%s'",
                    user_id_str
                )
                request.gateway_user_id   = None
                request.gateway_user_role = None
        else:
            request.gateway_user_id   = None
            request.gateway_user_role = None

        # Enforcement (Thực thi chặn đứng)
        # Nếu path này ĐÁNG LÝ phải là API (không nằm trong Public hay Web)
        # mà lại KHÔNG có ID từ Gateway truyền xuống -> Đích thị là bypass Gateway!
        if not _is_public(request.path) and request.gateway_user_id is None:
            logger.warning(f"Defense in Depth: Blocked unauthorized API access to {request.path}")
            return JsonResponse({
                "error": "Unauthorized", 
                "detail": "Gateway Identity Missing. Direct access to internal application is forbidden."
            }, status=401)

        response = self.get_response(request)
        return response