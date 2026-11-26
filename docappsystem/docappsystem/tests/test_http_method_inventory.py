"""Explicit HTTP method contracts for the application's own URL endpoints.

Place at: docappsystem/docappsystem/tests/test_http_method_inventory.py
Runs ONLY with --settings=docappsystem.settings_test (in-memory SQLite).

Read-only views: GET/HEAD; search views with GET-only implementations: GET.
Form views: GET/POST; mutations: POST. Django's built-in admin, the health
endpoint and favicon are covered separately and are not rewritten by this suite.

The read-only cases intentionally expose missing 405 enforcement (RED) before
source hardening. Keep the expected assertions unchanged during RED -> GREEN.
"""

from django.urls import reverse

from .test_http_method_role_matrix import MatrixFixtures


class HttpMethodInventoryFixtures(MatrixFixtures):
    """Construct arguments only from disposable in-memory fixture records."""

    def admin_safe_routes(self):
        # Four previously hardened screens (admin_home and
        # manage_specilizations are covered in ReadOnlyMethodPolicyTests).
        return (
            ("update_specilizations", (self.specialization.pk,)),
            ("viewdoctorlist", ()),
            ("viewdoctordetails", (self.doctor_reg.pk,)),
            ("viewdoctorappointmentlist", (self.doctor_reg.pk,)),
            ("viewpatientdetails", (self.own_appointment.pk,)),
            ("doctor_between_date_report", ()),
            ("website_update", ()),
        )

    def doctor_safe_routes(self):
        # doctor_home and view_appointment already have dedicated coverage.
        return (
            ("patientappointmentdetails", (self.own_appointment.pk,)),
            ("patientapprovedappointment", ()),
            ("patientcancelledappointment", ()),
            ("patientnewappointment", ()),
            ("patientlistappointment", ()),
            ("doctorappointmentlist", (self.own_appointment.pk,)),
            ("patientappointmentcompleted", ()),
            ("between_date_report", ()),
        )

    @staticmethod
    def public_safe_routes():
        return (("index", ()), ("base", ()), ("userbase", ()),
                ("user_search_appointment", ()))

    @staticmethod
    def authenticated_safe_routes():
        return (("profile", ()),)

    def urls(self, entries):
        return tuple(reverse(name, args=args) for name, args in entries)

    def assert_methods(self, client, entries, methods, expected):
        for path in self.urls(entries):
            for method in methods:
                with self.subTest(path=path, method=method):
                    response = self.request(client, method, path)
                    self.assertEqual(response.status_code, expected)


class RemainingReadOnlyMethodPolicyTests(HttpMethodInventoryFixtures):
    """New inventory: keep RED evidence separate from already GREEN controls."""

    def test_admin_read_only_reject_put(self):
        self.assert_methods(self.client_for(self.admin),
                            self.admin_safe_routes(), ("PUT",), 405)

    def test_doctor_read_only_reject_put(self):
        self.assert_methods(self.client_for(self.doctor),
                            self.doctor_safe_routes(), ("PUT",), 405)

    def test_public_read_only_reject_put(self):
        self.assert_methods(self.client_for(),
                            self.public_safe_routes(), ("PUT",), 405)

    def test_authenticated_profile_reject_put(self):
        self.assert_methods(self.client_for(self.doctor),
                            self.authenticated_safe_routes(), ("PUT",), 405)

    def test_authenticated_profile_reject_other_unsafe_methods(self):
        self.assert_methods(self.client_for(self.doctor),
                            self.authenticated_safe_routes(),
                            ("POST", "PATCH", "DELETE", "OPTIONS"), 405)

    def test_admin_read_only_reject_other_unsafe_methods(self):
        self.assert_methods(self.client_for(self.admin),
                            self.admin_safe_routes(),
                            ("POST", "PATCH", "DELETE", "OPTIONS"), 405)

    def test_doctor_read_only_reject_other_unsafe_methods(self):
        self.assert_methods(self.client_for(self.doctor),
                            self.doctor_safe_routes(),
                            ("POST", "PATCH", "DELETE", "OPTIONS"), 405)

    def test_public_read_only_reject_other_unsafe_methods(self):
        self.assert_methods(self.client_for(),
                            self.public_safe_routes(),
                            ("POST", "PATCH", "DELETE", "OPTIONS"), 405)

    def test_safe_routes_allow_get_and_head(self):
        for user, entries in (
            (self.admin, self.admin_safe_routes()),
            (self.doctor, self.doctor_safe_routes()),
            (self.doctor, self.authenticated_safe_routes()),
            (None, self.public_safe_routes()),
        ):
            client = self.client_for(user)
            self.assert_methods(client, entries, ("GET", "HEAD"), 200)

    def test_search_views_accept_get_only_and_reject_head(self):
        # Both implementations have an explicit if request.method == 'GET'.
        # @require_safe is NOT correct without also fixing their HEAD branch.
        for user, name in ((self.admin, "search_doctor"),
                           (self.doctor, "search_appointment")):
            client = self.client_for(user)
            path = reverse(name)
            with self.subTest(path=path, method="GET"):
                self.assertEqual(self.request(client, "GET", path).status_code, 200)
            with self.subTest(path=path, method="HEAD"):
                self.assertEqual(self.request(client, "HEAD", path).status_code, 405)

    def test_search_views_reject_other_methods(self):
        for user, name in ((self.admin, "search_doctor"),
                           (self.doctor, "search_appointment")):
            self.assert_methods(self.client_for(user), ((name, ()),),
                                ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"), 405)


class FormEndpointMethodPolicyTests(HttpMethodInventoryFixtures):
    """All app-managed GET+POST endpoints; skip live POST data mutations."""

    def test_get_post_form_endpoints_reject_disallowed_methods(self):
        # Paths already guarded with @require_http_methods(["GET", "POST"]).
        for user, name in (
            (self.admin, "add_specilizations"),
            (None, "docsignup"),
            (None, "appointment"),
            (self.admin, "change_password"),
        ):
            client = self.client_for(user)
            path = reverse(name)
            for method in ("HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"):
                with self.subTest(path=path, method=method):
                    self.assertEqual(self.request(client, method, path).status_code, 405)

    def test_get_post_form_endpoints_allow_get(self):
        for user, name in (
            (self.admin, "add_specilizations"),
            (None, "docsignup"),
            (None, "appointment"),
            (self.admin, "change_password"),
        ):
            client = self.client_for(user)
            with self.subTest(name=name):
                self.assertEqual(self.request(client, "GET", reverse(name)).status_code, 200)


class PostOnlyEndpointMethodPolicyTests(HttpMethodInventoryFixtures):
    """Existing POST-only routes must not accept any other HTTP method."""

    def post_only_cases(self):
        return (
            (None, "doLogin", ()),
            (None, "logout", ()),
            (self.admin, "delete_specilizations", (self.specialization.pk,)),
            (self.admin, "update_specilizations_details", ()),
            (self.admin, "update_website_details", ()),
            (self.admin, "approve_doctor", (self.doctor_reg.pk,)),
            (self.doctor, "patient_appointment_details_remark", ()),
            (self.doctor, "patientappointmentprescription", ()),
            (self.doctor, "profile_update", ()),
        )

    def test_post_only_endpoints_reject_every_other_method(self):
        # Tests use a CSRF-bearing client for PUT/PATCH/DELETE so that an
        # unexpected 403 does not mask missing HTTP method restriction.
        for user, name, args in self.post_only_cases():
            client = self.client_for(user)
            path = reverse(name, args=args)
            for method in ("GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"):
                with self.subTest(path=path, method=method):
                    self.assertEqual(self.request(client, method, path).status_code, 405)


class HealthGETMethodPolicyTests(HttpMethodInventoryFixtures):
    """Health URLs are explicitly GET-only and deliberately csrf_exempt."""

    def test_health_accepts_get(self):
        client = self.client_for()
        for path in ("/health/", "/health"):
            with self.subTest(path=path, method="GET"):
                self.assertEqual(self.request(client, "GET", path).status_code, 200)

    def test_health_rejects_non_get_methods(self):
        client = self.client_for()
        for path in ("/health/", "/health"):
            for method in ("HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
                with self.subTest(path=path, method=method):
                    self.assertEqual(self.request(client, method, path).status_code, 405)
