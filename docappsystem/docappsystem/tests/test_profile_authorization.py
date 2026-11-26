from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse


class ProfileAuthorizationTests(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user(
            username="doctor_p01",
            email="doctor_p01@example.test",
            password="OldStrong#123",
            user_type="2",
            profile_pic="test/avatar.png",
        )

    def test_anonymous_cannot_view_profile(self):
        response = self.client.get(reverse("profile"))

        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            response["Location"].startswith("/login/?next=")
        )

    def test_anonymous_cannot_access_password_page(self):
        response = self.client.get(
            reverse("change_password")
        )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            response["Location"].startswith("/login/?next=")
        )

    def test_anonymous_cannot_update_profile(self):
        response = self.client.post(
            reverse("profile_update"),
            {"first_name": "Unauthorized"},
        )

        self.assertEqual(response.status_code, 302)

    def test_authenticated_user_can_view_own_profile(self):
        self.client.force_login(self.user)

        response = self.client.get(reverse("profile"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.context["user"].pk,
            self.user.pk,
        )

    def test_profile_update_rejects_get(self):
        self.client.force_login(self.user)

        response = self.client.get(
            reverse("profile_update")
        )

        self.assertEqual(response.status_code, 405)

    def test_wrong_current_password_is_rejected(self):
        self.client.force_login(self.user)

        response = self.client.post(
            reverse("change_password"),
            {
                "old_password": "WrongPassword#123",
                "new_password1": "Better#Pass2026",
                "new_password2": "Better#Pass2026",
            },
        )

        self.assertEqual(response.status_code, 200)

        self.user.refresh_from_db()

        self.assertTrue(
            self.user.check_password("OldStrong#123")
        )

    def test_weak_new_password_is_rejected(self):
        self.client.force_login(self.user)

        response = self.client.post(
            reverse("change_password"),
            {
                "old_password": "OldStrong#123",
                "new_password1": "123",
                "new_password2": "123",
            },
        )

        self.assertEqual(response.status_code, 200)

        self.user.refresh_from_db()

        self.assertTrue(
            self.user.check_password("OldStrong#123")
        )

    def test_successful_password_change_keeps_session(self):
        self.client.force_login(self.user)

        response = self.client.post(
            reverse("change_password"),
            {
                "old_password": "OldStrong#123",
                "new_password1": "Better#Pass2026",
                "new_password2": "Better#Pass2026",
            },
        )

        self.assertEqual(response.status_code, 302)

        self.user.refresh_from_db()

        self.assertTrue(
            self.user.check_password("Better#Pass2026")
        )
        self.assertFalse(
            self.user.check_password("OldStrong#123")
        )

        # Session hiện tại vẫn được xác thực.
        response = self.client.get(reverse("profile"))

        self.assertEqual(response.status_code, 200)
