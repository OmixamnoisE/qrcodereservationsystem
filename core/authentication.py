from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from .models import Collector, Tourist  # Ensure Tourist is imported

User = get_user_model()


class ActiveBeachBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = User.objects.get(username=username)

            # Check if the user is a Collector
            try:
                collector = Collector.objects.get(user=user)
                if not collector.is_active:  # Reject if collector is inactive
                    return None
            except Collector.DoesNotExist:
                pass  # Not a collector

            # Check if the user is a Tourist
            try:
                tourist = Tourist.objects.get(user=user)
                if not tourist:  # Optionally, add any specific conditions for tourists here
                    return None
            except Tourist.DoesNotExist:
                pass  # Not a tourist

            # Authenticate the user if the password is correct
            if user.check_password(password):
                return user

        except User.DoesNotExist:
            return None

        return None
