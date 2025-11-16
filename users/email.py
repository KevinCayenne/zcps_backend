"""
Custom Djoser email classes.

These classes override Djoser's default email templates to use custom templates
and properly use FRONTEND_URL instead of Django Site domain.
"""

from django.conf import settings
from djoser import email


def parse_frontend_url():
    """
    Parse FRONTEND_URL to extract protocol and domain separately.

    This prevents double protocol issues when templates use {{ protocol }}://{{ domain }}
    format. The FRONTEND_URL can be specified with or without protocol.

    Returns:
        tuple: (protocol, domain) where protocol is 'http' or 'https',
               and domain is the URL without protocol

    Examples:
        - 'http://localhost:3000' -> ('http', 'localhost:3000')
        - 'https://app.example.com' -> ('https', 'app.example.com')
        - 'localhost:3000' -> ('http', 'localhost:3000')
        - 'example.com' -> ('https', 'example.com')
    """
    frontend_url = settings.FRONTEND_URL

    if frontend_url.startswith('http://'):
        return 'http', frontend_url.replace('http://', '')
    elif frontend_url.startswith('https://'):
        return 'https', frontend_url.replace('https://', '')
    else:
        # No protocol specified, assume http for localhost, https otherwise
        protocol = 'http' if 'localhost' in frontend_url or '127.0.0.1' in frontend_url else 'https'
        return protocol, frontend_url


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
        uid = context.get('uid')
        token = context.get('token')

        # Parse FRONTEND_URL to extract protocol and domain
        protocol, domain = parse_frontend_url()
        context['protocol'] = protocol
        context['domain'] = domain

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

        # Parse FRONTEND_URL to extract protocol and domain
        protocol, domain = parse_frontend_url()
        context['protocol'] = protocol
        context['domain'] = domain

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

        # Parse FRONTEND_URL to extract protocol and domain
        protocol, domain = parse_frontend_url()
        context['protocol'] = protocol
        context['domain'] = domain

        return context
