
from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse


class LoginSecuritySignalTests(TestCase):

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()

        cls.admin = User.objects.create_user(
            username="p02_admin",
            email="p02_admin@example.test",
            password="StrongAdmin#2026",
            user_type="1",
        )

        cls.doctor = User.objects.create_user(
            username="p02_doctor",
            email="p02_doctor@example.test",
            password="StrongDoctor#2026",
            user_type="2",
        )

        cls.inactive = User.objects.create_user(
            username="p02_inactive",
            email="p02_inactive@example.test",
            password="StrongInactive#2026",
            user_type="2",
            is_active=False,
        )

    def setUp(self):
        self.url = reverse("doLogin")

    def login_request(self, email, password):
        return self.client.post(
            self.url,
            {
                "email": email,
                "password": password,
            },
        )

    def test_non_post_methods_rejected(self):
        for method in ["get", "put", "patch", "delete"]:
            with self.subTest(method=method):
                response = getattr(self.client, method)(
                    self.url
                )

                self.assertEqual(response.status_code, 405)
                self.assertNotIn(
                    "X-Login-Status",
                    response
                )

    def test_wrong_password_returns_failed(self):
        response = self.login_request(
            self.admin.email,
            "WrongPassword#2026",
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response["X-Login-Status"],
            "failed",
        )
        self.assertNotIn(
            "_auth_user_id",
            self.client.session,
        )

    def test_unknown_email_returns_failed(self):
        response = self.login_request(
            "unknown@example.test",
            "WrongPassword#2026",
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response["X-Login-Status"],
            "failed",
        )

    def test_inactive_user_returns_failed(self):
        response = self.login_request(
            self.inactive.email,
            "StrongInactive#2026",
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response["X-Login-Status"],
            "failed",
        )
        self.assertNotIn(
            "_auth_user_id",
            self.client.session,
        )

    def test_admin_login_returns_success(self):
        response = self.login_request(
            self.admin.email,
            "StrongAdmin#2026",
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response["X-Login-Status"],
            "success",
        )
        self.assertEqual(
            self.client.session["_auth_user_id"],
            str(self.admin.pk),
        )

    def test_doctor_login_returns_success(self):
        response = self.login_request(
            self.doctor.email,
            "StrongDoctor#2026",
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response["X-Login-Status"],
            "success",
        )
        self.assertEqual(
            self.client.session["_auth_user_id"],
            str(self.doctor.pk),
        )

    def test_csrf_rejection_has_no_login_signal(self):
        csrf_client = Client(enforce_csrf_checks=True)

        response = csrf_client.post(
            self.url,
            {
                "email": self.admin.email,
                "password": "WrongPassword#2026",
            },
        )

        self.assertEqual(response.status_code, 403)
        self.assertNotIn(
            "X-Login-Status",
            response,
        )
