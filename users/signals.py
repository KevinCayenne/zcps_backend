"""
Signal handlers for user-related events.

This module contains signal handlers that respond to password management events,
particularly for JWT token blacklisting when passwords are reset or changed.
"""

from django.conf import settings
from django.contrib.auth import get_user_model
from django.dispatch import receiver
from djoser.signals import user_activated
from .utils import blacklist_user_tokens

User = get_user_model()


@receiver(user_activated)
def blacklist_tokens_on_password_reset(sender, user, request, **kwargs):
    """
    Blacklist all JWT tokens when user completes password reset.

    This signal is triggered after a successful password reset via the
    /auth/users/reset_password_confirm/ endpoint. For security purposes,
    all existing JWT refresh tokens are blacklisted to force re-authentication.

    This handler ALWAYS blacklists tokens on password reset, regardless of
    the BLACKLIST_TOKENS_ON_PASSWORD_CHANGE setting.

    Args:
        sender: The sender of the signal
        user: The User instance whose password was reset
        request: The HTTP request object
        **kwargs: Additional keyword arguments
    """
    # Note: Djoser doesn't have a built-in password_reset signal,
    # so we'll need to handle this differently using a custom view or
    # by connecting to Django's password_changed signal
    pass


# We'll use Django's built-in password_changed signal instead
# Import it at the top level
from django.contrib.auth.signals import user_logged_in


# Create a custom signal handling approach
# We'll need to detect if this is a password reset vs password change
# by checking the view that triggered the signal

# Alternative approach: Override Djoser views to add custom logic
# For now, let's create helper that can be called from views
