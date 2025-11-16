"""
Custom Djoser email classes.

These classes override Djoser's default email templates to use custom templates
and properly use FRONTEND_URL instead of Django Site domain.
"""

from django.conf import settings
from djoser import email


class ActivationEmail(email.ActivationEmail):
    """
    Custom activation email that uses FRONTEND_URL.

    Uses template: users/templates/email/activation.html
    """
    template_name = 'email/custom_activation.html'

    def get_context_data(self):
        """Override to use FRONTEND_URL instead of Django Site domain."""
        context = super().get_context_data()

        # Use FRONTEND_URL from settings instead of Django Site
        user = context.get('user')
        uid = context.get('uid')
        token = context.get('token')
        print(settings.FRONTEND_URL)

        # Override domain
        context['domain'] = settings.FRONTEND_URL

        # Reconstruct URL using FRONTEND_URL
        activation_url = settings.DJOSER.get('ACTIVATION_URL', 'auth/users/activation/{uid}/{token}')
        context['url'] = activation_url.format(uid=uid, token=token)

        return context


class ConfirmationEmail(email.ConfirmationEmail):
    """
    Custom confirmation email.

    Uses template: users/templates/email/confirmation.html
    """
    template_name = 'email/custom_confirmation.html'


class PasswordResetEmail(email.PasswordResetEmail):
    """
    Custom password reset email that uses FRONTEND_URL.

    Uses template: users/templates/email/password_reset.html
    """
    template_name = 'email/custom_password_reset.html'

    def get_context_data(self):
        """Override to use FRONTEND_URL instead of Django Site domain."""
        context = super().get_context_data()

        # Use FRONTEND_URL from settings
        uid = context.get('uid')
        token = context.get('token')

        # Override domain
        context['domain'] = settings.FRONTEND_URL

        # Reconstruct URL using FRONTEND_URL
        reset_url = settings.DJOSER.get('PASSWORD_RESET_CONFIRM_URL', 'password/reset/confirm/{uid}/{token}')
        context['url'] = reset_url.format(uid=uid, token=token)

        return context


class PasswordChangedConfirmationEmail(email.PasswordChangedConfirmationEmail):
    """
    Custom password changed confirmation email.

    Uses template: users/templates/email/password_changed_confirmation.html
    """
    template_name = 'email/custom_password_changed_confirmation.html'

    def get_context_data(self):
        """Override to use FRONTEND_URL instead of Django Site domain."""
        context = super().get_context_data()

        # Override domain
        context['domain'] = settings.FRONTEND_URL

        return context
