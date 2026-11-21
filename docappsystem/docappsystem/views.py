from django.shortcuts import render,redirect,HttpResponse
from dasapp.EmailBackEnd import EmailBackEnd
from django.contrib.auth import  logout,login
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from dasapp.models import CustomUser
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.views.decorators.http import require_POST

import logging

from django.conf import settings
from docappsystem.login_accounting import (
    AccountingError,
    LoginAccounting,
)

logger = logging.getLogger(__name__)

User = get_user_model()

def BASE(request):
    return render(request,'base.html')

def LOGIN(request):
    return render(request,'login.html')

def doLogout(request):
    logout(request)
    return redirect('login')

@require_POST
def doLogin(request):
    accounting_enabled = getattr(
        settings,
        "LOGIN_ACCOUNTING_ENABLED",
        False,
    )

    accounting = None
    admission = None
    client_ip = None

    def authentication_unavailable():
        response = HttpResponse(
            "Authentication temporarily unavailable",
            status=503,
        )
        response["Cache-Control"] = "no-store"
        return response

    # Use the same submitted identifier for accounting
    # and authentication. Only accounting canonicalizes its HMAC key.
    email = request.POST.get("email") or ""
    password = request.POST.get("password")

    if accounting_enabled and (
        not email.strip()
        or len(email) > 254
        or len(email.encode("utf-8")) > 512
    ):
        return HttpResponse(
            "Invalid login credentials",
            status=400,
        )

    # ========================================================
    # STEP 1 — ATOMIC ADMISSION
    # ========================================================
    # Chỉ hoạt động khi feature flag được bật.
    if accounting_enabled:
        client_ip = request.META.get(
            "HTTP_X_REAL_IP",
            "",
        )

        if not client_ip:
            logger.error(
                "[LOGIN_ACCOUNTING] Missing trusted client IP"
            )
            return authentication_unavailable()

        try:
            accounting = LoginAccounting()
            admission = accounting.admit(client_ip, email)

        except (AccountingError, ValueError):
            logger.exception(
                "[LOGIN_ACCOUNTING] Admission failed"
            )
            return authentication_unavailable()

        if admission.status in ("BACKOFF", "SATURATED"):
            response = HttpResponse(
                "Too many login requests",
                status=429,
            )
            response["Retry-After"] = "10"
            response["Cache-Control"] = "no-store"
            return response

        if (
            admission.status != "ADMITTED"
            or not admission.token
        ):
            logger.error(
                "[LOGIN_ACCOUNTING] Unexpected admission state"
            )
            return authentication_unavailable()

    # ========================================================
    # STEP 2 — AUTHENTICATE CREDENTIALS
    # ========================================================

    # Giữ cách gọi authentication hiện tại của project.
    user = EmailBackEnd.authenticate(
        request,
        username=email,
        password=password,
    )

    # ========================================================
    # STEP 3 — ATOMIC FINALIZATION
    # ========================================================
    # Phải hoàn tất trước khi tạo Django session.
    if accounting_enabled:
        outcome = (
            "success"
            if user is not None
            else "failed"
        )

        try:
            result = accounting.finalize(
                client_ip,
                email,
                admission.token,
                outcome,
            )

        except (AccountingError, ValueError):
            logger.exception(
                "[LOGIN_ACCOUNTING] Finalization failed"
            )
            return authentication_unavailable()

        if outcome == "success":
            confirmed = (result == "OK:SUCCESS")
        else:
            confirmed = result.startswith(("OK:FAILED:",))

        if not confirmed:
            logger.error(
                "[LOGIN_ACCOUNTING] Unexpected finalization: %s",
                result,
            )
            return authentication_unavailable()

    # ========================================================
    # STEP 4 — BUILD LOGIN RESPONSE
    # ========================================================
    if user is not None:
        # Chỉ tạo session sau khi finalization được xác nhận.
        login(request, user)

        user_type = user.user_type

        response = redirect("login")

        if user_type == "1":
            response = redirect("admin_home")

        elif user_type == "2":
            response = redirect("doctor_home")

        elif user_type == "3":
            response = HttpResponse("This is User panel")

        response["X-Login-Status"] = "success"

    else:
        messages.error(
            request,
            "Email or Password is not valid",
        )

        response = redirect("login")
        response["X-Login-Status"] = "failed"

    # ========================================================
    # STEP 5 — INTERNAL ACCOUNTING SIGNAL
    # ========================================================
    # Gateway chỉ bỏ legacy timer khi Django đã commit.
    if accounting_enabled:
        response["X-Login-Accounting"] = "sync-v3"

        if outcome == "failed":
            if result.endswith(":ACCOUNT_THRESHOLD_NEW"):
                response["X-Login-Alert"] = "account_guessing"

            elif admission.spray_threshold_new:
                response["X-Login-Alert"] = "password_spraying"

    return response

@login_required(login_url="/login/")
def PROFILE(request):
    return render(
        request,
        "profile.html",
        {"user": request.user},
    )

@login_required(login_url="/login/")
@require_POST
def PROFILE_UPDATE(request):
    if request.method == "POST":
        profile_pic = request.FILES.get('profile_pic')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        username = request.POST.get('username')
        print(profile_pic)

        try:
            customuser = CustomUser.objects.get(id = request.user.id)
            customuser.first_name = first_name
            customuser.last_name = last_name
            
            if profile_pic !=None and profile_pic != "":
               customuser.profile_pic = profile_pic
            customuser.save()
            messages.success(request,"Your profile has been updated successfully")
            return redirect('profile')

        except:
            messages.error(request,"Your profile updation has been failed")
    return render(request, 'profile.html')

@login_required(login_url="/login/")
def CHANGE_PASSWORD(request):
    if request.method == "POST":
        form = PasswordChangeForm(
            user=request.user,
            data=request.POST,
        )

        if form.is_valid():
            user = form.save()

            # Duy trì session hiện tại và cập nhật auth hash.
            update_session_auth_hash(request, user)

            messages.success(
                request,
                "Mật khẩu đã được thay đổi thành công.",
            )

            return redirect("change_password")

    else:
        form = PasswordChangeForm(user=request.user)

    return render(
        request,
        "change-password.html",
        {"form": form},
    )
