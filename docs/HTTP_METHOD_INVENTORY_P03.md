# HTTP Method Inventory — CSRF & Authentication Request Security

**Project:** Adaptive Security Gateway + ML for Layer 7  
**Environment:** local Docker Compose HTTPS lab  
**Scope:** Django application URL routes + custom Admin/Doctor panels  
**Status:** Draft inventory for RED → GREEN verification; not a P0.3 acceptance certificate  
**Baseline:** previously verified CSRF/role suite and 98 Django discovered tests (86 passed, 12 intentional live-Redis skips); 37-checkpoint authenticated HTTPS E2E; 19-checkpoint proxy-trust HTTPS E2E.

## Classification

- **SAFE** = GET, HEAD only (`@require_safe`). Unlisted methods must return 405 after permission and valid CSRF checks.
- **GET** = GET only (`@require_http_methods(["GET"])`). Use for views with an explicit `if request.method == "GET"` code path; HEAD must return 405 until HEAD is implemented.
- **FORM** = GET, POST only (`@require_http_methods(["GET", "POST"])`).
- **MUTATION** = POST only (`@require_POST`). Requires valid session/role where applicable, plus CSRF.
- **DENY** = intentional 403 identity-verification stub; keep denial semantics until the feature is implemented.
- **FRAMEWORK** = Django Admin / RedirectView; tested under framework-specific contracts; do not rewrite Django's internals with bulk decorators.

**Decorator order for protected views:** `@admin_required`/`@doctor_required` outermost, method decorator immediately underneath, preserving 302 for anonymous, 403 for wrong role and 405 for correct role with unsupported method. CSRF on unsafe requests may correctly produce 403 before the view.

## Public, authentication, session and profile routes

| URL | Handler | Method policy | Notes |
|---|---|---|---|
| `/` | `userviews.Index` | SAFE | Candidate for `@require_safe` |
| `/login/` | `views.LOGIN` | SAFE | Already hardened |
| `/doLogin/` | `views.doLogin` | MUTATION | Already hardened |
| `/logout/` | Django `LogoutView` wrapped with `require_POST` | MUTATION | Already hardened; HTML POST form with CSRF |
| `/health/`, `/health` | `health_check` | GET | Explicit health exemption from CSRF; do not change casually |
| `/favicon.ico` | Django `RedirectView` | FRAMEWORK | Not an authentication mutation |
| `/doctor/signup/` | `docviews.DOCSIGNUP` | FORM | Already limited GET/POST |
| `/base/` | `views.BASE` | SAFE | Candidate for `@require_safe` |
| `/userbase/` | `userviews.USERBASE` | SAFE | Candidate for `@require_safe` |
| `/userappointment/` | `userviews.create_appointment` | FORM | Already hardened GET/POST |
| `/User_SearchAppointment/` | `userviews.User_Search_Appointments` | SAFE | With `query`, intentionally denies unverifiable lookups 403 |
| `/ViewAppointmentDetails/<int:id>/` | `userviews.View_Appointment_Details` | DENY | Intentionally always 403; do not silently replace with a 405 policy |
| `/profile/` | `views.PROFILE` | SAFE | Candidate for `@require_safe` (authenticated) |
| `/profile/update/` | `views.PROFILE_UPDATE` | MUTATION | Already hardened |
| `/password/` | `views.CHANGE_PASSWORD` | FORM | Already hardened GET/POST |
| `/sys-admin-panel/…` | Django Admin site | FRAMEWORK | Access controlled by Django `is_staff` and relevant permissions |

## Custom Admin routes — role `user_type="1"`

| URL | Handler | Policy | Notes |
|---|---|---|---|
| `/admin/` | `ADMINHOME` | SAFE | Previously hardened |
| `/admin/specialization/` | `SPECIALIZATION` | FORM | Previously hardened |
| `/admin/manage-specialization/` | `MANAGESPECIALIZATION` | SAFE | Previously hardened |
| `/admin/doctor/<int:id>/approve/` | `APPROVE_DOCTOR` | MUTATION | Previously hardened |
| `/admin/delete-specialization/<int:id>/` | `DELETE_SPECIALIZATION` | MUTATION | Previously hardened |
| `/admin/update-specialization/<int:id>/` | `UPDATE_SPECIALIZATION` | SAFE | Candidate `@require_safe` |
| `/admin/update-specialization-details/` | `UPDATE_SPECIALIZATION_DETAILS` | MUTATION | Previously hardened |
| `/admin/doctor-list/` | `DoctorList` | SAFE | Candidate `@require_safe` |
| `/admin/view-doctor-details/<int:id>/` | `ViewDoctorDetails` | SAFE | Candidate `@require_safe` |
| `/admin/view-doctor-appointments/<int:id>/` | `ViewDoctorAppointmentList` | SAFE | Candidate `@require_safe` |
| `/admin/view-patient-details/<int:id>/` | `ViewPatientDetails` | SAFE | Candidate `@require_safe` |
| `/admin/search-doctor/` | `Search_Doctor` | GET | **Use `@require_http_methods(["GET"])`**; current HEAD has no response path |
| `/admin/doctor-report/` | `Doctor_Between_Date_Report` | SAFE | Candidate `@require_safe` |
| `/admin/website/update/` | `WEBSITE_UPDATE` | SAFE | Candidate `@require_safe`; despite URL name, displays form only |
| `/admin/website/update-details/` | `UPDATE_WEBSITE_DETAILS` | MUTATION | Previously hardened |

## Doctor routes — role `user_type="2"`

| URL | Handler | Policy | Notes |
|---|---|---|---|
| `/doctor/home/` | `DOCTORHOME` | SAFE | Previously hardened |
| `/doctor/view-appointment/` | `View_Appointment` | SAFE | Previously hardened |
| `/doctor/appointment-details/<int:id>/` | `Patient_Appointment_Details` | SAFE | Candidate `@require_safe`, ownership check required |
| `/doctor/appointment-remark/update/` | `Patient_Appointment_Details_Remark` | MUTATION | Previously hardened, ownership check required |
| `/doctor/appointments/approved/` | `Patient_Approved_Appointment` | SAFE | Candidate `@require_safe` |
| `/doctor/appointments/cancelled/` | `Patient_Cancelled_Appointment` | SAFE | Candidate `@require_safe` |
| `/doctor/appointments/new/` | `Patient_New_Appointment` | SAFE | Candidate `@require_safe` |
| `/doctor/appointments/list-approved/` | `Patient_List_Approved_Appointment` | SAFE | Candidate `@require_safe` |
| `/doctor/appointment-list/<int:id>/` | `DoctorAppointmentList` | SAFE | Candidate `@require_safe`, ownership check required |
| `/doctor/prescription/` | `Patient_Appointment_Prescription` | MUTATION | Previously hardened, ownership check required |
| `/doctor/completed/` | `Patient_Appointment_Completed` | SAFE | Candidate `@require_safe` |
| `/doctor/search-appointment/` | `Search_Appointments` | GET | **Use `@require_http_methods(["GET"])`**; current HEAD has no response path |
| `/doctor/report/` | `Between_Date_Report` | SAFE | Candidate `@require_safe` |

## Verification plan

1. **RED evidence:** Run only `RemainingReadOnlyMethodPolicyTests.test_admin_read_only_reject_put`, `.test_doctor_read_only_reject_put`, `.test_public_read_only_reject_put`, plus `.test_search_views_accept_get_only_and_reject_head`. Capture all mismatches and exceptions; do not change expected status codes to 200/500.
2. **Small patches:** Apply method decorators only to identified views. No changes to business logic or authorization, and no GitHub writes by the assistant.
3. **GREEN:** Run the complete `test_http_method_inventory.py` suite, then rerun `test_http_method_role_matrix.py` and `test_csrf_authentication_security.py`.
4. **Regression:** `bash tests/run-unit.sh django` using isolated in-memory SQLite. Count is expected to increase by the number of new methods discovered; 12 Redis live tests are still intentionally skipped.
5. **Runtime sync:** Rebuild Django image and recreate only local app and gateway, verifying healthy status.
6. **Admin/Doctor HTTPS E2E:** Run `nginx/tests/test_admin_doctor_session_https_e2e.sh`, using two disposable accounts with independent cookie jars; verify dashboard, wrong-role denial, rendered POST logout form and session invalidation.
7. **Final evidence:** Record commit SHA, run date, environment, commands, test totals, skipped tests, and unaddressed risks. Close P0.3 only after final checks.

**Explicit exclusions:** Production testing, full HTTP fuzzing, Redis AOF/recovery fault injection, and Django Admin framework internals. These have independent acceptance requirements.
