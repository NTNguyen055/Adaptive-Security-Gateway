from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth.models import AnonymousUser
from django.http import Http404
from django.test import RequestFactory, SimpleTestCase
from django.test import Client

from dasapp.models import Page
from dasapp.models import Appointment
from docappsystem.docviews import Patient_Appointment_Details
from django.urls import reverse

from io import BytesIO
from tempfile import TemporaryDirectory
from unittest.mock import patch

from PIL import Image
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings

class DoctorAppointmentAuthorizationTests(SimpleTestCase):

    def setUp(self):
        self.factory = RequestFactory()
        self.path = "/doctor/appointment-details/999999/"

    def make_request(self, user):
        request = self.factory.get(
            self.path,
            secure=True,
            HTTP_HOST="localhost",
        )
        request.user = user
        return request

    def test_anonymous_user_redirected_to_login(self):
        request = self.make_request(AnonymousUser())

        response = Patient_Appointment_Details(
            request, 999999
        )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            response["Location"].startswith("/login/")
        )

    def test_admin_cannot_access_doctor_appointment(self):
        admin = SimpleNamespace(
            is_authenticated=True,
            user_type="1",
        )

        request = self.make_request(admin)

        with patch(
            "docappsystem.docviews.get_object_or_404"
        ) as lookup:
            response = Patient_Appointment_Details(
                request, 999999
            )

        self.assertEqual(response.status_code, 403)
        lookup.assert_not_called()

    def test_doctor_query_requires_ownership(self):
        doctor = SimpleNamespace(
            is_authenticated=True,
            user_type="2",
        )

        request = self.make_request(doctor)

        with patch(
            "docappsystem.docviews.get_object_or_404",
            side_effect=Http404,
        ) as lookup:
            with self.assertRaises(Http404):
                Patient_Appointment_Details(
                    request, 999999
                )

        lookup.assert_called_once_with(
            Appointment,
            id=999999,
            doctor_id__admin=doctor,
        )

from django.test import TestCase
from dasapp.models import CustomUser, DoctorReg, Specialization

class DoctorAppointmentDatabaseTests(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.specialization = Specialization.objects.create(
            sname="Test Specialization"
        )

        cls.user_a = CustomUser.objects.create_user(
            username="doctor_a",
            password="test-password-a",
            user_type="2",
            profile_pic="test/doctor-a.png",
        )

        cls.user_b = CustomUser.objects.create_user(
            username="doctor_b",
            password="test-password-b",
            user_type="2",
            profile_pic="test/doctor-b.png",
        )

        cls.admin = CustomUser.objects.create_user(
            username="test_admin",
            password="test-password-admin",
            user_type="1",
            profile_pic="test/admin.png",
        )

        cls.doctor_a = DoctorReg.objects.create(
            admin=cls.user_a,
            mobilenumber="0123456789",
            specialization_id=cls.specialization,
        )

        cls.doctor_b = DoctorReg.objects.create(
            admin=cls.user_b,
            mobilenumber="0987654321",
            specialization_id=cls.specialization,
        )

        cls.appointment_a = Appointment.objects.create(
            appointmentnumber=100001,
            fullname="Test Patient A",
            mobilenumber="0123456789",
            email="patient-a@example.invalid",
            date_of_appointment="2026-12-01",
            time_of_appointment="10:00",
            doctor_id=cls.doctor_a,
        )

        cls.appointment_b = Appointment.objects.create(
            appointmentnumber=100002,
            fullname="Test Patient B",
            mobilenumber="0987654321",
            email="patient-b@example.invalid",
            date_of_appointment="2026-12-02",
            time_of_appointment="11:00",
            doctor_id=cls.doctor_b,
        )

    def setUp(self):
        self.factory = RequestFactory()

    def get_response(self, user, appointment):
        request = self.factory.get(
            f"/doctor/appointment-details/{appointment.pk}/",
            secure=True,
        )
        request.user = user
        return Patient_Appointment_Details(
            request,
            appointment.pk,
        )

    def test_doctor_can_view_own_appointment(self):
        response = self.get_response(
            self.user_a,
            self.appointment_a,
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Test Patient A")

    def test_doctor_cannot_view_other_appointment(self):
        with self.assertRaises(Http404):
            self.get_response(
                self.user_a,
                self.appointment_b,
            )

    def test_admin_cannot_view_doctor_appointment(self):
        response = self.get_response(
            self.admin,
            self.appointment_a,
        )

        self.assertEqual(response.status_code, 403)

    def test_anonymous_cannot_update_appointments(self):
        for path in [
            "/doctor/appointment-remark/update/",
            "/doctor/prescription/",
        ]:
            with self.subTest(path=path):
                response = self.client.post(path, {})
                self.assertEqual(response.status_code, 302)
                self.assertIn("/login/", response["Location"])

    def test_admin_cannot_update_appointments(self):
        self.client.force_login(self.admin)

        for path in [
            "/doctor/appointment-remark/update/",
            "/doctor/prescription/",
        ]:
            with self.subTest(path=path):
                response = self.client.post(path, {})
                self.assertEqual(response.status_code, 403)

    def test_doctor_cannot_update_other_appointment(self):
        self.client.force_login(self.user_a)

        response = self.client.post(
            "/doctor/appointment-remark/update/",
            {
                "pat_id": str(self.appointment_b.pk),
                "remark": "Unauthorized change",
                "status": "Approved",
            },
        )
        self.assertEqual(response.status_code, 404)

        response = self.client.post(
            "/doctor/prescription/",
            {
                "pat_id": str(self.appointment_b.pk),
                "prescription": "Unauthorized prescription",
                "recommendedtest": "Test",
                "status": "Completed",
            },
        )
        self.assertEqual(response.status_code, 404)

        self.appointment_b.refresh_from_db()
        self.assertEqual(self.appointment_b.status, "0")

    def test_doctor_can_update_own_remark(self):
        self.client.force_login(self.user_a)

        response = self.client.post(
            "/doctor/appointment-remark/update/",
            {
                "pat_id": str(self.appointment_a.pk),
                "remark": "Patient approved",
                "status": "Approved",
            },
        )

        self.assertEqual(response.status_code, 302)

        self.appointment_a.refresh_from_db()
        self.assertEqual(self.appointment_a.status, "Approved")
        self.assertEqual(
            self.appointment_a.remark,
            "Patient approved",
        )

    def test_doctor_can_update_own_prescription(self):
        self.appointment_a.status = "Approved"
        self.appointment_a.save(update_fields=["status"])
        self.client.force_login(self.user_a)

        response = self.client.post(
            "/doctor/prescription/",
            {
                "pat_id": str(self.appointment_a.pk),
                "prescription": "Test prescription",
                "recommendedtest": "Blood test",
                "status": "Completed",
            },
        )

        self.assertEqual(response.status_code, 302)

        self.appointment_a.refresh_from_db()
        self.assertEqual(self.appointment_a.status, "Completed")
        self.assertEqual(
            self.appointment_a.prescription,
            "Test prescription",
        )

    def test_mutation_endpoints_reject_get(self):
        self.client.force_login(self.user_a)

        for path in [
            "/doctor/appointment-remark/update/",
            "/doctor/prescription/",
        ]:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 405)

    def doctor_urls(self):
        return [
            reverse("doctor_home"),
            reverse("view_appointment"),
            reverse("patientappointmentdetails", args=[999999]),
            reverse("patient_appointment_details_remark"),
            reverse("patientapprovedappointment"),
            reverse("patientcancelledappointment"),
            reverse("patientnewappointment"),
            reverse("patientlistappointment"),
            reverse("doctorappointmentlist", args=[999999]),
            reverse("patientappointmentprescription"),
            reverse("patientappointmentcompleted"),
            reverse("search_appointment"),
            reverse("between_date_report"),
        ]

    def test_anonymous_denied_from_all_doctor_routes(self):
        for url in self.doctor_urls():
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 302)
                self.assertIn("/login/", response["Location"])

    def test_admin_denied_from_all_doctor_routes(self):
        self.client.force_login(self.admin)

        for url in self.doctor_urls():
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 403)

    def test_doctor_can_view_own_list_detail(self):
        self.client.force_login(self.user_a)

        response = self.client.get(
            reverse(
                "doctorappointmentlist",
                args=[self.appointment_a.pk],
            )
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Test Patient A")

    def test_doctor_cannot_view_other_list_detail(self):
        self.client.force_login(self.user_a)

        response = self.client.get(
            reverse(
                "doctorappointmentlist",
                args=[self.appointment_b.pk],
            )
        )

        self.assertEqual(response.status_code, 404)

from django.http import HttpResponse
from docappsystem.permissions import admin_required, doctor_required
from docappsystem.adminviews import ADMINHOME
from docappsystem.docviews import DOCTORHOME

class DashboardRoleTests(SimpleTestCase):

    def setUp(self):
        self.factory = RequestFactory()

    def make_request(self, path, role=None):
        request = self.factory.get(path, secure=True)

        if role is None:
            request.user = AnonymousUser()
        else:
            request.user = SimpleNamespace(
                is_authenticated=True,
                user_type=role,
            )

        return request

    def test_doctor_cannot_access_admin_dashboard(self):
        request = self.make_request("/admin/", "2")
        response = ADMINHOME(request)
        self.assertEqual(response.status_code, 403)

    def test_admin_cannot_access_doctor_dashboard(self):
        request = self.make_request("/doctor/home/", "1")
        response = DOCTORHOME(request)
        self.assertEqual(response.status_code, 403)

    def test_anonymous_cannot_access_admin_dashboard(self):
        request = self.make_request("/admin/")
        response = ADMINHOME(request)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            response["Location"].startswith("/login/")
        )

    def test_anonymous_cannot_access_doctor_dashboard(self):
        request = self.make_request("/doctor/home/")
        response = DOCTORHOME(request)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            response["Location"].startswith("/login/")
        )

    def test_admin_role_is_allowed(self):
        @admin_required
        def protected_view(request):
            return HttpResponse("OK")

        request = self.make_request("/admin/", "1")
        response = protected_view(request)
        self.assertEqual(response.status_code, 200)

    def test_doctor_role_is_allowed(self):
        @doctor_required
        def protected_view(request):
            return HttpResponse("OK")

        request = self.make_request("/doctor/home/", "2")
        response = protected_view(request)
        self.assertEqual(response.status_code, 200)

class AdminSpecializationDeletionTests(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.admin = CustomUser.objects.create_user(
            username="delete_test_admin",
            password="test-password",
            user_type="1",
        )
        cls.doctor = CustomUser.objects.create_user(
            username="delete_test_doctor",
            password="test-password",
            user_type="2",
        )

        cls.used = Specialization.objects.create(
            sname="Used Specialization"
        )
        cls.unused = Specialization.objects.create(
            sname="Unused Specialization"
        )

        cls.doctor_reg = DoctorReg.objects.create(
            admin=cls.doctor,
            mobilenumber="0123456789",
            specialization_id=cls.used,
        )

    def delete_url(self, specialization):
        return reverse(
            "delete_specilizations",
            args=[specialization.pk],
        )

    def test_anonymous_cannot_delete(self):
        response = self.client.post(
            self.delete_url(self.unused)
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            Specialization.objects.filter(
                pk=self.unused.pk
            ).exists()
        )

    def test_doctor_cannot_delete(self):
        self.client.force_login(self.doctor)
        response = self.client.post(
            self.delete_url(self.unused)
        )
        self.assertEqual(response.status_code, 403)
        self.assertTrue(
            Specialization.objects.filter(
                pk=self.unused.pk
            ).exists()
        )

    def test_delete_rejects_get(self):
        self.client.force_login(self.admin)
        response = self.client.get(
            self.delete_url(self.unused)
        )
        self.assertEqual(response.status_code, 405)

    def test_admin_can_delete_unused_specialization(self):
        self.client.force_login(self.admin)
        response = self.client.post(
            self.delete_url(self.unused)
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(
            Specialization.objects.filter(
                pk=self.unused.pk
            ).exists()
        )

    def test_cannot_delete_specialization_with_doctors(self):
        self.client.force_login(self.admin)
        response = self.client.post(
            self.delete_url(self.used)
        )
        self.assertEqual(response.status_code, 409)
        self.assertTrue(
            Specialization.objects.filter(
                pk=self.used.pk
            ).exists()
        )
        self.assertTrue(
            DoctorReg.objects.filter(
                pk=self.doctor_reg.pk
            ).exists()
        )

class AdminEndpointRoleCoverageTests(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.doctor = CustomUser.objects.create_user(
            username="rbac_coverage_doctor",
            password="test-password",
            user_type="2",
        )

    def admin_urls(self):
        return [
            reverse("admin_home"),
            reverse("add_specilizations"),
            reverse("manage_specilizations"),
            reverse("delete_specilizations", args=[999999]),
            reverse("update_specilizations", args=[999999]),
            reverse("update_specilizations_details"),
            reverse("viewdoctorlist"),
            reverse("viewdoctordetails", args=[999999]),
            reverse("viewdoctorappointmentlist", args=[999999]),
            reverse("viewpatientdetails", args=[999999]),
            reverse("search_doctor"),
            reverse("doctor_between_date_report"),
            reverse("website_update"),
            reverse("update_website_details"),
        ]

    def test_anonymous_denied_from_all_admin_routes(self):
        for url in self.admin_urls():
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 302)
                self.assertTrue(
                    response["Location"].startswith("/login/")
                )

    def test_doctor_denied_from_all_admin_routes(self):
        self.client.force_login(self.doctor)

        for url in self.admin_urls():
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 403)

    def test_doctor_cannot_post_to_admin_mutations(self):
        self.client.force_login(self.doctor)

        mutation_urls = [
            reverse("add_specilizations"),
            reverse("delete_specilizations", args=[999999]),
            reverse("update_specilizations_details"),
            reverse("update_website_details"),
        ]

        for url in mutation_urls:
            with self.subTest(url=url):
                response = self.client.post(url, {})
                self.assertEqual(response.status_code, 403)

class AdminSpecializationValidationTests(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.admin = CustomUser.objects.create_user(
            username="validation_admin",
            password="test-password",
            user_type="1",
        )
        cls.specialization = Specialization.objects.create(
            sname="Original Name",
        )

    def setUp(self):
        self.client.force_login(self.admin)

    def test_create_valid_specialization(self):
        response = self.client.post(
            reverse("add_specilizations"),
            {"specializationname": "  Cardiology  "},
        )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            Specialization.objects.filter(
                sname="Cardiology"
            ).exists()
        )

    def test_create_rejects_invalid_names(self):
        original_count = Specialization.objects.count()

        for name in ["   ", "X" * 201]:
            with self.subTest(name_length=len(name)):
                response = self.client.post(
                    reverse("add_specilizations"),
                    {"specializationname": name},
                )
                self.assertEqual(response.status_code, 400)

        self.assertEqual(
            Specialization.objects.count(),
            original_count,
        )

    def test_update_rejects_get(self):
        response = self.client.get(
            reverse("update_specilizations_details")
        )

        self.assertEqual(response.status_code, 405)

    def test_update_rejects_invalid_id(self):
        response = self.client.post(
            reverse("update_specilizations_details"),
            {"sep_id": "invalid", "sname": "Updated"},
        )

        self.assertEqual(response.status_code, 400)

    def test_update_rejects_invalid_names(self):
        for name in [" ", "X" * 201]:
            with self.subTest(name_length=len(name)):
                response = self.client.post(
                    reverse("update_specilizations_details"),
                    {
                        "sep_id": self.specialization.pk,
                        "sname": name,
                    },
                )
                self.assertEqual(response.status_code, 400)

        self.specialization.refresh_from_db()
        self.assertEqual(
            self.specialization.sname,
            "Original Name",
        )

    def test_update_valid_specialization(self):
        response = self.client.post(
            reverse("update_specilizations_details"),
            {
                "sep_id": self.specialization.pk,
                "sname": "  Updated Name  ",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.specialization.refresh_from_db()
        self.assertEqual(
            self.specialization.sname,
            "Updated Name",
        )

    def test_csrf_rejects_post_without_token(self):
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.admin)

        response = csrf_client.post(
            reverse("add_specilizations"),
            {"specializationname": "Unauthorized Creation"},
        )

        self.assertEqual(response.status_code, 403)
        self.assertFalse(
            Specialization.objects.filter(
                sname="Unauthorized Creation"
            ).exists()
        )

class AdminWebsiteUpdateTests(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.admin = CustomUser.objects.create_user(
            username="website_admin",
            password="test-password",
            user_type="1",
        )

        cls.page = Page.objects.create(
            pagetitle="Original Title",
            address="Original Address",
            aboutus="Original About",
            email="original@example.com",
            mobilenumber="0123456789",
        )

    def setUp(self):
        self.client.force_login(self.admin)
        self.url = reverse("update_website_details")

    def valid_data(self):
        return {
            "web_id": str(self.page.pk),
            "pagetitle": "Updated Title",
            "address": "Updated Address",
            "aboutus": "Updated About",
            "email": "updated@example.com",
            "mobilenumber": "0987654321",
        }

    def test_valid_update(self):
        response = self.client.post(
            self.url, self.valid_data()
        )

        self.assertEqual(response.status_code, 302)

        self.page.refresh_from_db()
        self.assertEqual(self.page.pagetitle, "Updated Title")
        self.assertEqual(self.page.email, "updated@example.com")

    def test_reject_get(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 405)

    def test_reject_invalid_id(self):
        data = self.valid_data()
        data["web_id"] = "invalid"

        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 400)

    def test_reject_invalid_fields(self):
        for field, value in [
            ("pagetitle", ""),
            ("email", "invalid-email"),
            ("mobilenumber", "1" * 16),
        ]:
            with self.subTest(field=field):
                data = self.valid_data()
                data[field] = value

                response = self.client.post(self.url, data)
                self.assertEqual(response.status_code, 400)

        self.page.refresh_from_db()
        self.assertEqual(self.page.pagetitle, "Original Title")

    def test_nonexistent_page_returns_404(self):
        data = self.valid_data()
        data["web_id"] = "999999"

        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 404)

    def test_csrf_rejects_missing_token(self):
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.admin)

        response = csrf_client.post(
            self.url, self.valid_data()
        )

        self.assertEqual(response.status_code, 403)

        self.page.refresh_from_db()
        self.assertEqual(self.page.pagetitle, "Original Title")

class DoctorRegistrationApprovalTests(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.specialization = Specialization.objects.create(
            sname="Registration Test",
        )

    def setUp(self):
        self.media_dir = TemporaryDirectory()
        self.addCleanup(self.media_dir.cleanup)

        self.media_settings = override_settings(
            MEDIA_ROOT=self.media_dir.name,
        )
        self.media_settings.enable()
        self.addCleanup(self.media_settings.disable)

        self.password = "Strong-2026-Test!Xp"
        self.email = "pending@example.invalid"
        self.username = "doctor_pending"

    def signup_data(self):
        image_buffer = BytesIO()
        Image.new("RGB", (1, 1), "white").save(
            image_buffer, format="PNG"
        )

        return {
            "first_name": "An",
            "last_name": "Nguyen",
            "username": self.username,
            "email": self.email,
            "mobno": "0123456789",
            "specialization_id": str(self.specialization.pk),
            "password": self.password,
            "pic": SimpleUploadedFile(
                "doctor.png",
                image_buffer.getvalue(),
                content_type="image/png",
            ),
        }

    def register_doctor(self):
        response = self.client.post(
            reverse("docsignup"),
            self.signup_data(),
        )
        self.assertEqual(response.status_code, 302)

        return CustomUser.objects.get(username=self.username)

    def test_signup_creates_inactive_doctor(self):
        user = self.register_doctor()

        self.assertEqual(user.user_type, "2")
        self.assertFalse(user.is_active)
        self.assertTrue(user.check_password(self.password))

        self.assertTrue(
            DoctorReg.objects.filter(
                admin=user,
                specialization_id=self.specialization,
            ).exists()
        )

    def test_inactive_doctor_cannot_login(self):
        self.register_doctor()

        response = self.client.post(
            reverse("doLogin"),
            {
                "email": self.email,
                "password": self.password,
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_activated_doctor_can_login(self):
        user = self.register_doctor()

        # Mô phỏng quyết định kích hoạt của quản trị viên.
        user.is_active = True
        user.save(update_fields=["is_active"])

        with patch("docappsystem.views.record_login_attempt"):
            response = self.client.post(
                reverse("doLogin"),
                {
                    "email": self.email,
                    "password": self.password,
                },
            )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            self.client.session["_auth_user_id"],
            str(user.pk),
        )

    def test_invalid_specialization_creates_no_user(self):
        data = self.signup_data()
        data["specialization_id"] = "999999"

        response = self.client.post(
            reverse("docsignup"),
            data,
        )

        self.assertEqual(response.status_code, 400)
        self.assertFalse(
            CustomUser.objects.filter(
                username=self.username
            ).exists()
        )

    def test_missing_fields_rejected(self):
        response = self.client.post(
            reverse("docsignup"),
            {"username": self.username},
        )

        self.assertEqual(response.status_code, 400)
        self.assertFalse(
            CustomUser.objects.filter(
                username=self.username
            ).exists()
        )

class DoctorApprovalWorkflowTests(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.admin = CustomUser.objects.create_user(
            username="approval_admin",
            password="test-password",
            user_type="1",
        )

        cls.doctor_user = CustomUser.objects.create_user(
            username="approval_doctor",
            password="test-password",
            user_type="2",
            is_active=False,
        )

        cls.specialization = Specialization.objects.create(
            sname="Approval Test"
        )

        cls.doctor = DoctorReg.objects.create(
            admin=cls.doctor_user,
            mobilenumber="0123456789",
            specialization_id=cls.specialization,
        )

    def setUp(self):
        self.url = reverse(
            "approve_doctor",
            args=[self.doctor.pk],
        )

    def test_admin_can_approve_doctor(self):
        self.client.force_login(self.admin)

        response = self.client.post(self.url)

        self.assertEqual(response.status_code, 302)
        self.doctor_user.refresh_from_db()
        self.assertTrue(self.doctor_user.is_active)

    def test_anonymous_cannot_approve(self):
        response = self.client.post(self.url)

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response["Location"])

        self.doctor_user.refresh_from_db()
        self.assertFalse(self.doctor_user.is_active)

    def test_doctor_cannot_approve(self):
        other_doctor = CustomUser.objects.create_user(
            username="approval_other_doctor",
            password="test-password",
            user_type="2",
        )
        self.client.force_login(other_doctor)

        response = self.client.post(self.url)

        self.assertEqual(response.status_code, 403)

        self.doctor_user.refresh_from_db()
        self.assertFalse(self.doctor_user.is_active)

    def test_approve_rejects_get(self):
        self.client.force_login(self.admin)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 405)

    def test_cannot_approve_twice(self):
        self.client.force_login(self.admin)

        self.doctor_user.is_active = True
        self.doctor_user.save(update_fields=["is_active"])

        response = self.client.post(self.url)

        self.assertEqual(response.status_code, 409)

    def test_nonexistent_doctor_returns_404(self):
        self.client.force_login(self.admin)

        response = self.client.post(
            reverse("approve_doctor", args=[999999])
        )

        self.assertEqual(response.status_code, 404)

    def test_csrf_rejects_approval_without_token(self):
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.admin)

        response = csrf_client.post(self.url)

        self.assertEqual(response.status_code, 403)

        self.doctor_user.refresh_from_db()
        self.assertFalse(self.doctor_user.is_active)
