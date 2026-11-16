# Import các hàm render giao diện, chuyển hướng và trả về HTTP response
from multiprocessing import context
from django.shortcuts import render, redirect, HttpResponse

from django.contrib.auth.decorators import login_required
from dasapp.models import DoctorReg, Specialization, CustomUser, Appointment
from django.contrib import messages
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

from datetime import datetime

from django.db.models import Q
from django.shortcuts import get_object_or_404
from django.http import HttpResponseForbidden
from django.http import HttpResponse, HttpResponseBadRequest
from django.views.decorators.http import require_POST
from .permissions import doctor_required

from django.db import transaction
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.views.decorators.http import require_http_methods

# View đăng ký bác sĩ
@require_http_methods(["GET", "POST"])
def DOCSIGNUP(request):
    specializations = Specialization.objects.all()

    if request.method == "POST":
        pic = request.FILES.get("pic")
        first_name = (request.POST.get("first_name") or "").strip()
        last_name = (request.POST.get("last_name") or "").strip()
        username = (request.POST.get("username") or "").strip()
        email = (request.POST.get("email") or "").strip()
        mobno = (request.POST.get("mobno") or "").strip()
        specialization_id = request.POST.get("specialization_id", "")
        password = request.POST.get("password") or ""

        # Kiểm tra các trường bắt buộc.
        if not all([
            pic, first_name, last_name, username,
            email, mobno, specialization_id, password,
        ]):
            return HttpResponseBadRequest("Missing required fields")

        if (
            not mobno.isascii()
            or not mobno.isdigit()
            or not 9 <= len(mobno) <= 11
        ):
            return HttpResponseBadRequest("Invalid phone number")

        # Xác minh chuyên khoa trước khi tạo tài khoản.
        if (
            not specialization_id.isascii()
            or not specialization_id.isdigit()
        ):
            return HttpResponseBadRequest("Invalid specialization")

        specialization = Specialization.objects.filter(
            pk=int(specialization_id)
        ).first()

        if specialization is None:
            return HttpResponseBadRequest("Invalid specialization")

        if CustomUser.objects.filter(
            email__iexact=email
        ).exists():
            messages.warning(request, "Email already exists")
            return redirect("docsignup")

        if CustomUser.objects.filter(
            username__iexact=username
        ).exists():
            messages.warning(request, "Username already exists")
            return redirect("docsignup")

        user = CustomUser(
            first_name=first_name,
            last_name=last_name,
            username=username,
            email=email,
            user_type="2",
            is_active=False,
            profile_pic=pic,
        )

        user.set_password(password)

        try:
            validate_password(password, user=user)
            user.full_clean()
        except ValidationError:
            return HttpResponseBadRequest(
                "Invalid registration information"
            )

        # Tạo đồng thời user và hồ sơ bác sĩ trong database.
        with transaction.atomic():
            user.save()

            DoctorReg.objects.create(
                admin=user,
                mobilenumber=mobno,
                specialization_id=specialization,
            )

        messages.success(
            request,
            "Registration received. "
            "Please wait for administrator approval.",
        )
        return redirect("docsignup")

    return render(
        request,
        "doc/docreg.html",
        {"specialization": specializations},
    )

# Trang dashboard chính của bác sĩ
@doctor_required
def DOCTORHOME(request):
    doctor_admin = request.user
    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)

    allaptcount = Appointment.objects.filter(doctor_id=doctor_reg).count()
    newaptcount = Appointment.objects.filter(status='0', doctor_id=doctor_reg).count()
    appaptcount = Appointment.objects.filter(status='Approved', doctor_id=doctor_reg).count()
    canaptcount = Appointment.objects.filter(status='Cancelled', doctor_id=doctor_reg).count()
    comaptcount = Appointment.objects.filter(status='Completed', doctor_id=doctor_reg).count()

    context = {
        'newaptcount': newaptcount,
        'allaptcount': allaptcount,
        'appaptcount': appaptcount,
        'canaptcount': canaptcount,
        'comaptcount': comaptcount
    }
    return render(request, 'doc/dochome.html', context)

# Xem danh sách lịch hẹn của bác sĩ
@doctor_required
def View_Appointment(request):
    try:
        doctor_admin = request.user
        doctor_reg = DoctorReg.objects.get(admin=doctor_admin)

        # FIX 1: Thêm .order_by('-id') để khắc phục lỗi UnorderedObjectListWarning
        # Sắp xếp lịch hẹn mới nhất lên đầu, giúp Paginator cắt trang chính xác
        view_appointment = Appointment.objects.filter(doctor_id=doctor_reg).order_by('-id')

        paginator = Paginator(view_appointment, 5)
        page = request.GET.get('page')

        try:
            view_appointment = paginator.page(page)
        except PageNotAnInteger:
            view_appointment = paginator.page(1)
        except EmptyPage:
            view_appointment = paginator.page(paginator.num_pages)

        context = {'view_appointment': view_appointment}

    except Exception as e:
        context = {'error_message': str(e)}

    return render(request, 'doc/view_appointment.html', context)

# Xem chi tiết lịch hẹn của bệnh nhân
@doctor_required
@login_required(login_url="/login/")
def Patient_Appointment_Details(request, id):
    # Chỉ tài khoản bác sĩ mới được truy cập.
    if str(request.user.user_type) != "2":
        return HttpResponseForbidden("Forbidden")

    # Chỉ cho phép bác sĩ xem lịch hẹn thuộc về mình.
    appointment = get_object_or_404(
        Appointment,
        id=id,
        doctor_id__admin=request.user,
    )

    return render(
        request,
        "doc/patient_appointment_details.html",
        {"patientdetails": [appointment]},
    )

# Cập nhật trạng thái lịch hẹn và ghi chú
@doctor_required
@require_POST
def Patient_Appointment_Details_Remark(request):
    patient_id = request.POST.get("pat_id", "")
    remark = request.POST.get("remark", "").strip()
    status = request.POST.get("status", "")

    if not patient_id.isascii() or not patient_id.isdigit():
        return HttpResponseBadRequest("Invalid appointment ID")

    if not remark or len(remark) > 250:
        return HttpResponseBadRequest("Invalid remark")

    if status not in {"Approved", "Cancelled"}:
        return HttpResponseBadRequest("Invalid status")

    appointment = get_object_or_404(
        Appointment,
        id=patient_id,
        doctor_id__admin=request.user,
    )

    if appointment.status != "0":
        return HttpResponse(
            "Invalid appointment state",
            status=409,
        )

    appointment.remark = remark
    appointment.status = status
    appointment.save(update_fields=["remark", "status"])

    messages.success(request, "Status Update successfully")
    return redirect("view_appointment")

# Xem danh sách lịch hẹn đã duyệt
@doctor_required
def Patient_Approved_Appointment(request):
    doctor_admin = request.user
    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)
    # FIX: Thêm order_by('-id')
    patientdetails1 = Appointment.objects.filter(status='Approved', doctor_id=doctor_reg).order_by('-id')
    context = {'patientdetails1': patientdetails1}
    return render(request, 'doc/patient_app_appointment.html', context)

# Xem danh sách lịch hẹn đã hủy
@doctor_required
def Patient_Cancelled_Appointment(request):
    doctor_admin = request.user
    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)
    # FIX: Thêm order_by('-id')
    patientdetails1 = Appointment.objects.filter(status='Cancelled', doctor_id=doctor_reg).order_by('-id')
    context = {'patientdetails1': patientdetails1}
    return render(request, 'doc/patient_app_appointment.html', context)

# Xem danh sách lịch hẹn mới
@doctor_required
def Patient_New_Appointment(request):
    doctor_admin = request.user
    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)
    # FIX: Thêm order_by('-id')
    patientdetails1 = Appointment.objects.filter(status='0', doctor_id=doctor_reg).order_by('-id')
    context = {'patientdetails1': patientdetails1}
    return render(request, 'doc/patient_app_appointment.html', context)

# Xem danh sách lịch hẹn đã duyệt (dạng list khác)
@doctor_required
def Patient_List_Approved_Appointment(request):
    doctor_admin = request.user
    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)
    # FIX: Thêm order_by('-id')
    patientdetails1 = Appointment.objects.filter(status='Approved', doctor_id=doctor_reg).order_by('-id')
    context = {'patientdetails1': patientdetails1}
    return render(request, 'doc/patient_list_app_appointment.html', context)

# Xem chi tiết lịch hẹn
@doctor_required
def DoctorAppointmentList(request, id):
    appointment = get_object_or_404(
        Appointment,
        pk=id,
        doctor_id__admin=request.user,
    )

    return render(
        request,
        "doc/doctor_appointment_list_details.html",
        {"patientdetails": [appointment]},
    )

# Cập nhật đơn thuốc và xét nghiệm
@doctor_required
@require_POST
def Patient_Appointment_Prescription(request):
    patient_id = request.POST.get("pat_id", "")
    prescription = request.POST.get("prescription", "").strip()
    recommendedtest = request.POST.get("recommendedtest", "").strip()
    status = request.POST.get("status", "")

    if not patient_id.isascii() or not patient_id.isdigit():
        return HttpResponseBadRequest("Invalid appointment ID")

    if not prescription or not recommendedtest:
        return HttpResponseBadRequest("Missing prescription data")

    if status != "Completed":
        return HttpResponseBadRequest("Invalid status")

    appointment = get_object_or_404(
        Appointment,
        id=patient_id,
        doctor_id__admin=request.user,
    )

    if appointment.status != "Approved":
        return HttpResponse(
            "Invalid appointment state",
            status=409,
        )

    appointment.prescription = prescription
    appointment.recommendedtest = recommendedtest
    appointment.status = "Completed"

    appointment.save(
        update_fields=[
            "prescription",
            "recommendedtest",
            "status",
        ]
    )

    messages.success(request, "Status Update successfully")
    return redirect("view_appointment")

# Xem lịch hẹn đã hoàn thành
@doctor_required
def Patient_Appointment_Completed(request):
    doctor_admin = request.user
    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)
    # FIX: Thêm order_by('-id')
    patientdetails1 = Appointment.objects.filter(status='Completed', doctor_id=doctor_reg).order_by('-id')
    context = {'patientdetails1': patientdetails1}
    return render(request, 'doc/patient_list_app_appointment.html', context)

# Tìm kiếm lịch hẹn theo tên hoặc mã lịch hẹn
@doctor_required
def Search_Appointments(request):
    doctor_admin = request.user
    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)

    if request.method == "GET":
        query = request.GET.get('query', '')
        if query:
            # FIX 2: Vá Lỗ hổng Logic dữ liệu bằng Q Objects
            # Logic cũ không có dấu ngoặc () nên sẽ bị lỗi ưu tiên toán tử AND/OR, 
            # có thể làm rò rỉ lịch hẹn của Bác sĩ khác. 
            # Dùng Q() object giúp khóa chặt điều kiện: (Thuộc về Bác Sĩ NÀY) VÀ (Tên HOẶC Mã khớp query)
            patient = Appointment.objects.filter(
                Q(doctor_id=doctor_reg) & 
                (Q(fullname__icontains=query) | Q(appointmentnumber__icontains=query))
            ).order_by('-id')

            messages.success(request, "Search against " + query)
            return render(request, 'doc/search-appointment.html', {'patient': patient, 'query': query})
        else:
            return render(request, 'doc/search-appointment.html', {})

# Báo cáo lịch hẹn theo khoảng ngày
@doctor_required
def Between_Date_Report(request):
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    patient = []

    doctor_admin = request.user
    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)

    if start_date and end_date:
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        except ValueError:
            return render(request, 'doc/between-dates-report.html', {'error_message': 'Invalid date format'})

        # FIX 3: Viết gộp điều kiện filter cho an toàn và hiệu suất cao hơn thay vì dùng toán tử &
        # Đồng thời thêm order_by('-id')
        patient = Appointment.objects.filter(
            doctor_id=doctor_reg,
            created_at__range=(start_date, end_date)
        ).order_by('-id')

    return render(request, 'doc/between-dates-report.html', {'patient': patient, 'start_date': start_date, 'end_date': end_date})