"""
Custom permission classes for authentication and authorization.

Includes 2FA enforcement and temporary token validation.
"""

from rest_framework import permissions
from django.conf import settings


class Require2FAEnabled(permissions.BasePermission):
    """
    Permission class to enforce 2FA requirement based on admin setting.

    If REQUIRE_2FA_FOR_ALL_USERS is True, all authenticated users must
    have 2FA enabled before accessing protected endpoints.
    """

    message = 'Two-factor authentication is required. Please enable 2FA on your account first.'

    def has_permission(self, request, view):
        """
        Check if user has 2FA enabled when globally required.

        Returns:
            bool: True if 2FA not required or user has 2FA enabled
        """
        # Check if 2FA is globally required
        require_2fa = getattr(settings, 'REQUIRE_2FA_FOR_ALL_USERS', False)

        # If not required globally, allow access
        if not require_2fa:
            return True

        # If required, check if user has 2FA enabled
        if request.user and request.user.is_authenticated:
            return request.user.is_2fa_enabled

        return False


class IsTemporary2FAToken(permissions.BasePermission):
    """
    Permission class that only allows temporary 2FA tokens.

    Used to restrict endpoints to only accept temporary tokens
    issued during the 2FA login flow.
    """

    message = 'This endpoint requires a temporary 2FA token.'

    def has_permission(self, request, view):
        """
        Check if request uses a temporary 2FA token.

        Returns:
            bool: True if token has temp_2fa claim
        """
        # Check if auth header exists
        if not hasattr(request, 'auth') or request.auth is None:
            return False

        # Check for temp_2fa claim in token
        return request.auth.get('temp_2fa', False) is True
