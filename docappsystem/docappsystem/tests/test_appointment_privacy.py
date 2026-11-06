from django.test import RequestFactory, SimpleTestCase

from docappsystem.userviews import (
    User_Search_Appointments,
    View_Appointment_Details,
)


class AppointmentPrivacyTests(SimpleTestCase):

    def setUp(self):
        self.factory = RequestFactory()

    def test_search_with_query_requires_verification(self):
        request = self.factory.get(
            "/User_SearchAppointment/",
            {"query": "test"},
        )

        response = User_Search_Appointments(request)

        self.assertEqual(response.status_code, 403)

    def test_appointment_details_requires_verification(self):
        request = self.factory.get(
            "/ViewAppointmentDetails/1/"
        )

        response = View_Appointment_Details(request, id=1)

        self.assertEqual(response.status_code, 403)
