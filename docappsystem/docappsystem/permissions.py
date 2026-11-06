from functools import wraps

from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden


def role_required(expected_role):
    """Require Django session authentication and the specified user role."""

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            user_role = str(
                getattr(request.user, "user_type", "")
            )

            if user_role != expected_role:
                return HttpResponseForbidden("Forbidden")

            return view_func(request, *args, **kwargs)

        return login_required(
            wrapper,
            login_url="/login/",
        )

    return decorator


admin_required = role_required("1")
doctor_required = role_required("2")