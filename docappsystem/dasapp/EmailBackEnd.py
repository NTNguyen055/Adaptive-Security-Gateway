from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend


class EmailBackEnd(ModelBackend):

    def authenticate(self, username=None, password=None, **kwargs):
        if not username or not password:
            return None

        UserModel = get_user_model()

        try:
            user = UserModel.objects.get(email=username)
        except (UserModel.DoesNotExist, UserModel.MultipleObjectsReturned):
            return None

        if user.check_password(password) and user.is_active:
            return user

        return None