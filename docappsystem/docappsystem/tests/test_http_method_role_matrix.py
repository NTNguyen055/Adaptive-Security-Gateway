"""Django security regression: session roles, CSRF, ownership, and HTTP methods.

Place at docappsystem/docappsystem/tests/test_http_method_role_matrix.py.
Run against docappsystem.settings_test (SQLite in-memory; no live DB/Redis).

The existing-boundary suite documents currently implemented controls. The
read-only-policy suite deliberately tests a stronger 405 contract and may be
RED until those read-only views receive explicit method decorators.
"""

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from dasapp.models import Appointment, DoctorReg, Specialization


class MatrixFixtures(TestCase):
    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.admin = User.objects.create_user(
            username="matrix_admin", email="matrix-admin@example.invalid",
            password="MatrixAdmin!2026", user_type="1", is_active=True,
            is_staff=False, profile_pic="test/matrix_admin.png",
        )
        cls.staff = User.objects.create_user(
            username="matrix_staff", email="matrix-staff@example.invalid",
            password="MatrixStaff!2026", user_type="1", is_active=True,
            is_staff=True, profile_pic="test/matrix_staff.png",
        )
        cls.doctor = User.objects.create_user(
            username="matrix_doctor", email="matrix-doctor@example.invalid",
            password="MatrixDoctor!2026", user_type="2", is_active=True,
            is_staff=False, profile_pic="test/matrix_doctor.png",
        )
        cls.other_doctor = User.objects.create_user(
            username="matrix_other_doctor", email="matrix-other@example.invalid",
            password="MatrixOther!2026", user_type="2", is_active=True,
            is_staff=False, profile_pic="test/matrix_other.png",
        )
        cls.specialization = Specialization.objects.create(
            sname="Matrix existing specialization"
        )
        cls.doctor_reg = DoctorReg.objects.create(
            admin=cls.doctor, mobilenumber="0912345678",
            specialization_id=cls.specialization,
        )
        cls.other_doctor_reg = DoctorReg.objects.create(
            admin=cls.other_doctor, mobilenumber="0987654321",
            specialization_id=cls.specialization,
        )
        cls.own_appointment = Appointment.objects.create(
            appointmentnumber=88771001, fullname="Matrix Own Appointment",
            email="own@example.invalid", mobilenumber="0912345678",
            date_of_appointment="2099-01-01", time_of_appointment="10:00",
            doctor_id=cls.doctor_reg, status="0",
        )
        cls.foreign_appointment = Appointment.objects.create(
            appointmentnumber=88771002, fullname="Matrix Foreign Appointment",
            email="foreign@example.invalid", mobilenumber="0987654321",
            date_of_appointment="2099-01-02", time_of_appointment="11:00",
            doctor_id=cls.other_doctor_reg, status="0",
        )

    def client_for(self, user=None):
        """Client with actual CSRF enforcement and a same-origin HTTPS cookie."""
        client = Client(enforce_csrf_checks=True)
        if user is not None:
            client.force_login(user)
        response = client.get(reverse("login"), secure=True, HTTP_HOST="localhost")
        self.assertEqual(response.status_code, 200)
        self.assertIn("csrftoken", client.cookies)
        return client

    def request(self, client, method, path, *, data=None, csrf=True,
                origin="https://localhost", extra=None):
        headers = {"secure": True, "HTTP_HOST": "localhost"}
        if origin is not None:
            headers["HTTP_ORIGIN"] = origin
        if csrf:
            headers["HTTP_X_CSRFTOKEN"] = client.cookies["csrftoken"].value
        if extra:
            headers.update(extra)
        method = method.upper()
        if method in ("GET", "HEAD", "OPTIONS", "DELETE"):
            return getattr(client, method.lower())(path, **headers)
        if method == "POST":
            return client.post(path, data=data or {}, **headers)
        return client.generic(
            method, path, data=b"", content_type="application/octet-stream",
            **headers,
        )


class RoleAndMutationBoundaryTests(MatrixFixtures):
    """Expected GREEN on the current security baseline."""

    def test_anonymous_cannot_reach_custom_role_dashboards(self):
        client = self.client_for()
        for path in (reverse("admin_home"), reverse("doctor_home"),
                     reverse("profile")):
            with self.subTest(path=path):
                result = self.request(client, "GET", path)
                self.assertEqual(result.status_code, 302)
                self.assertTrue(result["Location"].startswith("/login/?next="))

    def test_forged_identity_headers_do_not_replace_session(self):
        client = self.client_for()
        headers = {
            "HTTP_X_USER_ID": str(self.admin.pk),
            "HTTP_X_USER_ROLE": "admin",
            "HTTP_AUTHORIZATION": "Bearer forged-token",
        }
        for path in (reverse("admin_home"), reverse("doctor_home"),
                     reverse("profile")):
            with self.subTest(path=path):
                result = self.request(client, "GET", path, extra=headers)
                self.assertEqual(result.status_code, 302)

    def test_custom_role_separation(self):
        admin_client = self.client_for(self.admin)
        doctor_client = self.client_for(self.doctor)
        self.assertEqual(
            self.request(admin_client, "GET", reverse("admin_home")).status_code,
            200,
        )
        self.assertEqual(
            self.request(doctor_client, "GET", reverse("admin_home")).status_code,
            403,
        )
        self.assertEqual(
            self.request(doctor_client, "GET", reverse("doctor_home")).status_code,
            200,
        )
        self.assertEqual(
            self.request(admin_client, "GET", reverse("doctor_home")).status_code,
            403,
        )

    def test_django_admin_staff_flag_is_distinct_from_custom_admin_role(self):
        unauthenticated = self.client_for()
        role_admin_not_staff = self.client_for(self.admin)
        django_staff = self.client_for(self.staff)
        path = "/sys-admin-panel/"
        self.assertEqual(self.request(unauthenticated, "GET", path).status_code, 302)
        self.assertEqual(self.request(role_admin_not_staff, "GET", path).status_code, 302)
        self.assertEqual(self.request(django_staff, "GET", path).status_code, 200)

    def test_doctor_cannot_read_appointments_owned_by_other_doctor(self):
        client = self.client_for(self.doctor)
        for name in ("patientappointmentdetails", "doctorappointmentlist"):
            with self.subTest(route=name):
                path = reverse(name, args=[self.foreign_appointment.pk])
                self.assertEqual(self.request(client, "GET", path).status_code, 404)

    def test_mutating_endpoints_reject_get_with_correct_role(self):
        admin_client = self.client_for(self.admin)
        doctor_client = self.client_for(self.doctor)
        cases = (
            (admin_client, reverse("delete_specilizations", args=[self.specialization.pk])),
            (admin_client, reverse("update_specilizations_details")),
            (admin_client, reverse("update_website_details")),
            (admin_client, reverse("approve_doctor", args=[self.doctor_reg.pk])),
            (doctor_client, reverse("patient_appointment_details_remark")),
            (doctor_client, reverse("patientappointmentprescription")),
            (admin_client, reverse("profile_update")),
        )
        for client, path in cases:
            with self.subTest(path=path):
                self.assertEqual(self.request(client, "GET", path).status_code, 405)
        self.assertTrue(Specialization.objects.filter(pk=self.specialization.pk).exists())

    def test_mutating_endpoints_reject_unsafe_wrong_methods_with_csrf(self):
        admin_client = self.client_for(self.admin)
        doctor_client = self.client_for(self.doctor)
        cases = (
            (admin_client, reverse("delete_specilizations", args=[self.specialization.pk])),
            (admin_client, reverse("update_specilizations_details")),
            (admin_client, reverse("update_website_details")),
            (doctor_client, reverse("patient_appointment_details_remark")),
            (doctor_client, reverse("patientappointmentprescription")),
            (admin_client, reverse("profile_update")),
        )
        for client, path in cases:
            for method in ("PUT", "PATCH", "DELETE"):
                with self.subTest(path=path, method=method):
                    response = self.request(client, method, path)
                    self.assertEqual(response.status_code, 405)
        self.assertTrue(Specialization.objects.filter(pk=self.specialization.pk).exists())

    def test_csrf_is_required_before_admin_or_doctor_mutation(self):
        admin_client = self.client_for(self.admin)
        doctor_client = self.client_for(self.doctor)
        old_name = self.specialization.sname
        old_status = self.own_appointment.status
        admin_path = reverse("add_specilizations")
        doctor_path = reverse("patient_appointment_details_remark")
        self.assertEqual(self.request(
            admin_client, "POST", admin_path, csrf=False,
            data={"specializationname": "CSRF bypass attempt"},
        ).status_code, 403)
        self.assertEqual(self.request(
            doctor_client, "POST", doctor_path, csrf=False,
            data={"pat_id": str(self.own_appointment.pk),
                  "remark": "Unauthorized", "status": "Approved"},
        ).status_code, 403)
        self.specialization.refresh_from_db()
        self.own_appointment.refresh_from_db()
        self.assertEqual(self.specialization.sname, old_name)
        self.assertEqual(self.own_appointment.status, old_status)
        self.assertFalse(Specialization.objects.filter(sname="CSRF bypass attempt").exists())

    def test_cross_origin_post_is_denied_before_admin_mutation(self):
        client = self.client_for(self.admin)
        response = self.request(
            client, "POST", reverse("add_specilizations"),
            origin="https://attacker.example",
            data={"specializationname": "Origin bypass attempt"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Specialization.objects.filter(sname="Origin bypass attempt").exists())

    def test_wrong_role_cannot_mutate_admin_or_doctor_resources(self):
        doctor_client = self.client_for(self.doctor)
        admin_client = self.client_for(self.admin)
        self.assertEqual(self.request(
            doctor_client, "POST", reverse("add_specilizations"),
            data={"specializationname": "Doctor-created privilege escalation"},
        ).status_code, 403)
        self.assertFalse(Specialization.objects.filter(
            sname="Doctor-created privilege escalation"
        ).exists())
        self.assertEqual(self.request(
            admin_client, "POST", reverse("patient_appointment_details_remark"),
            data={"pat_id": str(self.own_appointment.pk),
                  "remark": "Admin as doctor", "status": "Approved"},
        ).status_code, 403)
        self.own_appointment.refresh_from_db()
        self.assertEqual(self.own_appointment.status, "0")

    def test_doctor_cannot_change_another_doctors_appointment(self):
        client = self.client_for(self.doctor)
        result = self.request(
            client, "POST", reverse("patient_appointment_details_remark"),
            data={"pat_id": str(self.foreign_appointment.pk),
                  "remark": "Cross-tenant attempt", "status": "Approved"},
        )
        self.assertEqual(result.status_code, 404)
        self.foreign_appointment.refresh_from_db()
        self.assertEqual(self.foreign_appointment.status, "0")
        self.assertEqual(self.foreign_appointment.remark, "0")

    def test_authorized_admin_and_doctor_mutations_work(self):
        admin_client = self.client_for(self.admin)
        doctor_client = self.client_for(self.doctor)
        name = "Authorized matrix specialization"
        self.assertEqual(self.request(
            admin_client, "POST", reverse("add_specilizations"),
            data={"specializationname": name},
        ).status_code, 302)
        self.assertEqual(Specialization.objects.filter(sname=name).count(), 1)
        self.assertEqual(self.request(
            doctor_client, "POST", reverse("patient_appointment_details_remark"),
            data={"pat_id": str(self.own_appointment.pk),
                  "remark": "Authorized by doctor", "status": "Approved"},
        ).status_code, 302)
        self.own_appointment.refresh_from_db()
        self.assertEqual(self.own_appointment.status, "Approved")
        self.assertEqual(self.own_appointment.remark, "Authorized by doctor")


class ReadOnlyMethodPolicyTests(MatrixFixtures):
    """Target 405 contract: potentially RED on read-only views without decorators.

    These tests have no persistent side effects and are separate from the
    confirmed role/CSRF controls above. Inspect failures before hardening.
    """

    def test_admin_read_only_pages_reject_put(self):
        client = self.client_for(self.admin)
        for path in (reverse("admin_home"), reverse("manage_specilizations")):
            with self.subTest(path=path):
                self.assertEqual(self.request(client, "PUT", path).status_code, 405)

    def test_doctor_read_only_pages_reject_put(self):
        client = self.client_for(self.doctor)
        for path in (reverse("doctor_home"), reverse("view_appointment")):
            with self.subTest(path=path):
                self.assertEqual(self.request(client, "PUT", path).status_code, 405)
