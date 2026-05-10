from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.db import connection, transaction
from django.views.generic import RedirectView

from django.core.cache import cache

# Import thư viện auth mặc định của Django để dùng hàm Logout
from django.contrib.auth import views as auth_views

# Import views
from . import views, adminviews, docviews, userviews

# ============================================================
# HEALTH CHECK
# ============================================================
@csrf_exempt
@require_http_methods(["GET"])
def health_check(request):
    """
    Lightweight health check cho Docker, gateway, và Jenkins.
    Kiểm tra DB connection (trong transaction) và Redis cache.
    """
    checks = {}
    healthy = True

    # Kiểm tra DB - Sử dụng transaction.atomic để cô lập check an toàn
    try:
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
        checks["db"] = "ok"
    except Exception as e:
        checks["db"] = f"error: {type(e).__name__}"
        healthy = False

    # Kiểm tra Redis cache
    try:
        cache.set("_health_ping", "1", timeout=5)
        val = cache.get("_health_ping")
        checks["cache"] = "ok" if val == "1" else "miss"
        if val != "1":
            healthy = False
    except Exception as e:
        # Cache down có thể chỉ cảnh báo chứ không làm sập hệ thống (tuỳ logic của bạn)
        checks["cache"] = f"error: {type(e).__name__}"
        checks["cache_warn"] = True

    status_code = 200 if healthy else 503
    return JsonResponse(
        {"status": "healthy" if healthy else "unhealthy", "checks": checks},
        status=status_code,
    )

# ============================================================
# URL PATTERNS (CẤU HÌNH ĐƯỜNG DẪN ĐẦY ĐỦ)
# ============================================================
urlpatterns = [

    # ── PUBLIC & AUTH (Không yêu cầu JWT) ─────────────────────
    path("login/",   views.LOGIN,   name="login"),
    path("doLogin/", views.doLogin, name="doLogin"),
    
    # Logout: Sử dụng built-in của Django để xóa Session sạch sẽ
    path("logout/",  auth_views.LogoutView.as_view(next_page='login'), name="logout"),
    
    # Điều hướng favicon.ico về thư mục static
    path("favicon.ico", RedirectView.as_view(url='/static/favicon.ico', permanent=True)),

    # Health check — match cả /health/ và /health để tránh lỗi redirect 301
    path("health/", health_check, name="health_check"),
    path("health",  health_check),

    # Doctor signup — public
    path("doctor/signup/", docviews.DOCSIGNUP, name="docsignup"),

    # ── BASE / USER ──────────────────────────────────────────
    # FIX: Sửa thành userviews.Index
    path("",          userviews.Index,    name="index"),
    path("base/",     views.BASE,         name="base"),
    path("userbase/", userviews.USERBASE, name="userbase"),

    path("userappointment/",
         userviews.create_appointment, name="appointment"),
    path("User_SearchAppointment/",
         userviews.User_Search_Appointments, name="user_search_appointment"),

    # NÂNG CẤP: Dùng <int:id> thay vì <str:id> để chống injection
    path("ViewAppointmentDetails/<int:id>/",
         userviews.View_Appointment_Details, name="viewappointmentdetails"),

    # ── PROFILE ──────────────────────────────────────────────
    path("profile/",         views.PROFILE,          name="profile"),
    path("profile/update/",  views.PROFILE_UPDATE,   name="profile_update"),
    path("password/",        views.CHANGE_PASSWORD,  name="change_password"),

    # ── DJANGO ADMIN ─────────────────────────────────────────
    # /admin/ được nginx.conf xử lý với security pipeline riêng (Hardened)
    path("sys-admin-panel/", admin.site.urls),

    # ── CUSTOM ADMIN PANEL ───────────────────────────────────
    path("admin/",
         adminviews.ADMINHOME, name="admin_home"),

    path("admin/specialization/",
         adminviews.SPECIALIZATION, name="add_specilizations"),
    path("admin/manage-specialization/",
         adminviews.MANAGESPECIALIZATION, name="manage_specilizations"),

    # NÂNG CẤP: Ép kiểu <int:id> cho các tham số xóa/sửa
    path("admin/delete-specialization/<int:id>/",
         adminviews.DELETE_SPECIALIZATION, name="delete_specilizations"),
    path("admin/update-specialization/<int:id>/",
         adminviews.UPDATE_SPECIALIZATION, name="update_specilizations"),
    path("admin/update-specialization-details/",
         adminviews.UPDATE_SPECIALIZATION_DETAILS, name="update_specilizations_details"),

    path("admin/doctor-list/",
         adminviews.DoctorList, name="viewdoctorlist"),
    path("admin/view-doctor-details/<int:id>/",
         adminviews.ViewDoctorDetails, name="viewdoctordetails"),
    path("admin/view-doctor-appointments/<int:id>/",
         adminviews.ViewDoctorAppointmentList, name="viewdoctorappointmentlist"),
    path("admin/view-patient-details/<int:id>/",
         adminviews.ViewPatientDetails, name="viewpatientdetails"),

    path("admin/search-doctor/",
         adminviews.Search_Doctor, name="search_doctor"),
    path("admin/doctor-report/",
         adminviews.Doctor_Between_Date_Report, name="doctor_between_date_report"),

    path("admin/website/update/",
         adminviews.WEBSITE_UPDATE, name="website_update"),
    path("admin/website/update-details/",
         adminviews.UPDATE_WEBSITE_DETAILS, name="update_website_details"),

    # ── DOCTOR PANEL ─────────────────────────────────────────
    path("doctor/home/",
         docviews.DOCTORHOME, name="doctor_home"),

    path("doctor/view-appointment/",
         docviews.View_Appointment, name="view_appointment"),
    path("doctor/appointment-details/<int:id>/",
         docviews.Patient_Appointment_Details, name="patientappointmentdetails"),
    path("doctor/appointment-remark/update/",
         docviews.Patient_Appointment_Details_Remark,
         name="patient_appointment_details_remark"),

    path("doctor/appointments/approved/",
         docviews.Patient_Approved_Appointment, name="patientapprovedappointment"),
    path("doctor/appointments/cancelled/",
         docviews.Patient_Cancelled_Appointment, name="patientcancelledappointment"),
    path("doctor/appointments/new/",
         docviews.Patient_New_Appointment, name="patientnewappointment"),
    path("doctor/appointments/list-approved/",
         docviews.Patient_List_Approved_Appointment, name="patientlistappointment"),

    path("doctor/appointment-list/<int:id>/",
         docviews.DoctorAppointmentList, name="doctorappointmentlist"),
    path("doctor/prescription/",
         docviews.Patient_Appointment_Prescription,
         name="patientappointmentprescription"),
    path("doctor/completed/",
         docviews.Patient_Appointment_Completed, name="patientappointmentcompleted"),

    path("doctor/search-appointment/",
         docviews.Search_Appointments, name="search_appointment"),
    path("doctor/report/",
         docviews.Between_Date_Report, name="between_date_report"),
]

# ── STATIC & MEDIA FILES ──────────────────────────────────────
if settings.DEBUG:
    from django.conf.urls.static import static
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)