from datetime import datetime

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db import transaction
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_POST, require_http_methods

from dasapp.models import (
    CustomUser,
    Specialization,
    DoctorReg,
    Appointment,
    Page,
)

from .permissions import admin_required

@admin_required
def ADMINHOME(request):
    doctor_count = DoctorReg.objects.all().count
    specialization_count = Specialization.objects.all().count
    context = {
        'doctor_count':doctor_count,
        'specialization_count':specialization_count,

    } 
    return render(request,'admin/adminhome.html',context)

@admin_required
@require_http_methods(["GET", "POST"])
def SPECIALIZATION(request):
    if request.method == "GET":
        return render(request, "admin/specialization.html")

    name = (request.POST.get("specializationname") or "").strip()

    if not 1 <= len(name) <= 200:
        return HttpResponseBadRequest("Invalid specialization name")

    Specialization.objects.create(sname=name)

    messages.success(request, "Specialization added successfully")
    return redirect("add_specilizations")

@admin_required
def MANAGESPECIALIZATION(request):
    specialization = Specialization.objects.all()
    context = {'specialization':specialization,

    }
    return render(request,'admin/manage_specialization.html',context)

@admin_required
@require_POST
def DELETE_SPECIALIZATION(request, id):
    specialization = get_object_or_404(
        Specialization,
        pk=id,
    )

    # Không xóa chuyên khoa đang có bác sĩ liên kết.
    if DoctorReg.objects.filter(
        specialization_id=specialization
    ).exists():
        return HttpResponse(
            "Cannot delete a specialization with doctors.",
            status=409,
        )

    specialization.delete()

    messages.success(
        request,
        "Specialization deleted successfully."
    )
    return redirect("manage_specilizations")

@admin_required
def UPDATE_SPECIALIZATION(request,id):
    specialization = Specialization.objects.get(id=id)
    
    context = {
         'specialization':specialization,
    }

    return render(request,'admin/update_specialization.html',context)

@admin_required
@require_POST
def UPDATE_SPECIALIZATION_DETAILS(request):
    raw_id = request.POST.get("sep_id", "")
    name = (request.POST.get("sname") or "").strip()

    try:
        specialization_id = int(raw_id)
    except (TypeError, ValueError):
        return HttpResponseBadRequest("Invalid specialization ID")

    if not 0 < specialization_id <= 9223372036854775807:
        return HttpResponseBadRequest("Invalid specialization ID")

    if not 1 <= len(name) <= 200:
        return HttpResponseBadRequest("Invalid specialization name")

    specialization = get_object_or_404(
        Specialization,
        pk=specialization_id,
    )

    specialization.sname = name
    specialization.save(update_fields=["sname"])

    messages.success(
        request,
        "Specialization updated successfully",
    )
    return redirect("manage_specilizations")

@admin_required
def DoctorList(request):
    doctorlist = DoctorReg.objects.all()
    context = {'doctorlist':doctorlist,

    }
    return render(request,'admin/doctor-list.html',context)

@admin_required
def ViewDoctorDetails(request,id):
    doctorlist1=DoctorReg.objects.filter(id=id)
    context={'doctorlist1':doctorlist1

    }

    return render(request,'admin/doctor-details.html',context)

@admin_required
def ViewDoctorAppointmentList(request,id):
    patientdetails=Appointment.objects.filter(doctor_id=id)
    context={'patientdetails':patientdetails

    }

    return render(request,'admin/doctor_appointment_list.html',context)

@admin_required
def ViewPatientDetails(request,id):
    patientdetails=Appointment.objects.filter(id=id)
    context={'patientdetails':patientdetails

    }

    return render(request,'admin/patient_appointment_details.html',context)

@admin_required
def Search_Doctor(request):
    if request.method == "GET":
        query = request.GET.get('query', '')
        if query:
            # Filter records where email or mobilenumber contains the query
            searchdoc = DoctorReg.objects.filter(mobilenumber__icontains=query) | DoctorReg.objects.filter(admin__first_name__icontains=query) | DoctorReg.objects.filter(admin__last_name__icontains=query)
            messages.info(request, "Search against " + query)
            return render(request, 'admin/search-doctor.html', {'searchdoc': searchdoc, 'query': query})
        else:
            print("No Record Found")
            return render(request, 'admin/search-doctor.html', {})

@admin_required
def Doctor_Between_Date_Report(request):
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')

    doctor = []

    if start_date and end_date:
        # Validate the date inputs
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        except ValueError:
            return render(request, 'admin/doctor-between-date.html', {'doctor': doctor, 'error_message': 'Invalid date format'})

        # Filter visitors between the given date range
        doctor = DoctorReg.objects.filter(regdate_at__range=(start_date, end_date))

    return render(request, 'admin/doctor-between-date.html', {'doctor': doctor,'start_date':start_date,'end_date':end_date})

@admin_required
def WEBSITE_UPDATE(request):
    page = Page.objects.all()
    context = {"page":page,

    }
    return render(request,'admin/website.html',context)

@admin_required
@require_POST
def UPDATE_WEBSITE_DETAILS(request):
    raw_id = request.POST.get("web_id", "")

    if not raw_id.isascii() or not raw_id.isdigit():
        return HttpResponseBadRequest("Invalid page ID")

    page_id = int(raw_id)

    if not 0 < page_id <= 9223372036854775807:
        return HttpResponseBadRequest("Invalid page ID")

    page = get_object_or_404(Page, pk=page_id)

    page.pagetitle = request.POST.get("pagetitle", "").strip()
    page.address = request.POST.get("address", "").strip()
    page.aboutus = request.POST.get("aboutus", "").strip()
    page.email = request.POST.get("email", "").strip()
    page.mobilenumber = request.POST.get("mobilenumber", "").strip()

    try:
        page.full_clean()
    except ValidationError:
        return HttpResponseBadRequest("Invalid website information")

    page.save()

    messages.success(
        request,
        "Website information updated successfully",
    )

    return redirect("website_update")

@admin_required
@require_POST
def APPROVE_DOCTOR(request, id):
    doctor = get_object_or_404(DoctorReg, pk=id)

    if doctor.admin_id is None:
        return HttpResponse("Doctor account missing", status=409)

    with transaction.atomic():
        user = get_object_or_404(
            CustomUser.objects.select_for_update(),
            pk=doctor.admin_id,
        )

        if str(user.user_type) != "2":
            return HttpResponse("Invalid doctor role", status=409)

        if user.is_active:
            return HttpResponse("Already activated", status=409)

        user.is_active = True
        user.save(update_fields=["is_active"])

    messages.success(request, "Doctor account activated")
    return redirect("viewdoctorlist")