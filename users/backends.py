"""
Custom authentication backends for Django boilerplate.

Provides authentication using either email or username.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.db.models import Q

User = get_user_model()


class EmailOrUsernameModelBackend(ModelBackend):
    """
    Custom authentication backend that allows users to log in with either email or username.

    This backend checks both the username and email fields to authenticate users,
    providing flexibility for login credentials.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        Authenticate user with either username or email.

        Args:
            request: The HTTP request object
            username: The username or email to authenticate with
            password: The user's password
            **kwargs: Additional keyword arguments

        Returns:
            User object if authentication succeeds, None otherwise
        """
        if username is None or password is None:
            return None

        try:
            # Try to fetch the user by searching for either username or email
            user = User.objects.get(
                Q(username=username) | Q(email=username)
            )
        except User.DoesNotExist:
            # Run the default password hasher once to reduce timing
            # difference between existing and non-existing users
            User().set_password(password)
            return None
        except User.MultipleObjectsReturned:
            # Handle edge case where multiple users have the same email
            # (shouldn't happen due to unique constraint)
            return None

        # Check the password and return the user if valid
        if user.check_password(password) and self.user_can_authenticate(user):
            return user

        return None
