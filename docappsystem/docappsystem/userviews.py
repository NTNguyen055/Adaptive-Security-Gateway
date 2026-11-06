from django.shortcuts import render,redirect,HttpResponse
from dasapp.models import DoctorReg,Specialization,CustomUser,Appointment,Page
import random
from datetime import datetime
from django.contrib import messages
from django.http import HttpResponseForbidden

def USERBASE(request):
    return render(request, "userbase.html", {})

def Index(request):
    doctorview = DoctorReg.objects.all()
    page = Page.objects.all()

    context = {'doctorview': doctorview,
    'page':page,
    }
    return render(request, 'index.html',context)

def create_appointment(request):
    doctorview = DoctorReg.objects.all()
    page = Page.objects.all()

    if request.method == "POST":
        appointmentnumber = random.randint(100000000, 999999999)
        fullname = request.POST.get('fullname')
        email = request.POST.get('email')
        mobilenumber = request.POST.get('mobilenumber')
        date_of_appointment = request.POST.get('date_of_appointment')
        time_of_appointment = request.POST.get('time_of_appointment')
        doctor_id = request.POST.get('doctor_id')
        additional_msg = request.POST.get('additional_msg')

        # Retrieve the DoctorReg instance using the doctor_id
        doc_instance = DoctorReg.objects.get(id=doctor_id)

        # Validate that date_of_appointment is greater than today's date
        try:
            appointment_date = datetime.strptime(date_of_appointment, '%Y-%m-%d').date()
            today_date = datetime.now().date()

            if appointment_date <= today_date:
                # If the appointment date is not in the future, display an error message
                messages.error(request, "Please select a date in the future for your appointment")
                return redirect('appointment')  # Redirect back to the appointment page
        except ValueError:
            # Handle invalid date format error
            messages.error(request, "Invalid date format")
            return redirect('appointment')  # Redirect back to the appointment page

        # Create a new Appointment instance with the provided data
        appointmentdetails = Appointment.objects.create(
            appointmentnumber=appointmentnumber,
            fullname=fullname,
            email=email,
            mobilenumber=mobilenumber,
            date_of_appointment=date_of_appointment,
            time_of_appointment=time_of_appointment,
            doctor_id=doc_instance,
            additional_msg=additional_msg
        )

        # Display a success message
        messages.success(request, "Your Appointment Request Has Been Sent. We Will Contact You Soon")

        return redirect('appointment')

    context = {'doctorview': doctorview,
    'page':page}
    return render(request, 'appointment.html', context)

def User_Search_Appointments(request):
    query = request.GET.get("query", "").strip()

    if query:
        return HttpResponseForbidden(
            "Appointment lookup requires identity verification."
        )

    return render(
        request,
        "search-appointment.html",
        {"page": Page.objects.all()}
    )

def View_Appointment_Details(request, id):
    return HttpResponseForbidden(
        "Appointment details require identity verification."
    )




