"""
Middleware for Two-Factor Authentication enforcement.

Blocks authenticated users from accessing protected endpoints when 2FA is enforced
but the user hasn't enabled 2FA.
"""

import logging
from django.http import JsonResponse
from users.models import TwoFactorSettings

logger = logging.getLogger(__name__)


class TwoFactorEnforcementMiddleware:
    """
    Middleware to enforce 2FA requirement for all authenticated users.

    When TwoFactorSettings.enforce_2fa_for_all_users is True, blocks access
    to protected endpoints for users who haven't enabled 2FA.
    """

    # Paths that are exempt from 2FA enforcement
    EXEMPT_PATHS = [
        '/auth/2fa/enable/',
        '/auth/2fa/enable/verify/',
        '/auth/email/verify/',
        '/auth/email/verify/send/',
        '/auth/jwt/create/',
        '/auth/jwt/refresh/',
        '/auth/jwt/verify/',
        '/auth/logout/',
        '/admin/',
        '/api/',
    ]

    def __init__(self, get_response):
        """Initialize middleware."""
        self.get_response = get_response

    def __call__(self, request):
        """Process request and enforce 2FA if required."""

        # Check if user is authenticated
        if not request.user.is_authenticated:
            # Not authenticated, let request pass
            return self.get_response(request)

        # Check if path is exempt from enforcement
        if self._is_path_exempt(request.path):
            # Exempt path, let request pass
            return self.get_response(request)

        # Get TwoFactorSettings to check enforcement policy
        try:
            settings_obj = TwoFactorSettings.get_solo()
        except Exception as e:
            logger.error(f"Failed to retrieve TwoFactorSettings in middleware: {str(e)}")
            # If we can't get settings, let request pass (fail open for availability)
            return self.get_response(request)

        # Check if 2FA enforcement is enabled
        if not settings_obj.enforce_2fa_for_all_users:
            # Enforcement not enabled, let request pass
            return self.get_response(request)

        # Check if user has 2FA enabled
        if request.user.is_2fa_enabled:
            # User has 2FA enabled, let request pass
            return self.get_response(request)

        # User doesn't have 2FA enabled but enforcement is on - block request
        logger.warning(
            f"2FA enforcement blocked user {request.user.id} ({request.user.email}) "
            f"from accessing {request.path}"
        )

        return JsonResponse(
            {
                'error': 'Two-factor authentication is required. Please enable 2FA at /auth/2fa/enable/',
                'required_action': 'enable_2fa',
                'endpoint': '/auth/2fa/enable/'
            },
            status=403
        )

    def _is_path_exempt(self, path):
        """
        Check if the given path is exempt from 2FA enforcement.

        Args:
            path: Request path to check

        Returns:
            bool: True if path is exempt, False otherwise
        """
        for exempt_path in self.EXEMPT_PATHS:
            if path.startswith(exempt_path):
                return True
        return False
