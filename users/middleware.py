"""
Middleware for Two-Factor Authentication enforcement.

Blocks authenticated users from accessing protected endpoints when 2FA is enforced
but the user hasn't enabled 2FA.
"""

import logging
from django.http import JsonResponse
from users.models import TwoFactorSettings
from users.twofactor_utils import get_twofactor_settings

logger = logging.getLogger(__name__)


class TwoFactorEnforcementMiddleware:
    """
    Middleware to enforce 2FA requirement for all authenticated users.

    When TwoFactorSettings.enforce_2fa_for_all_users is True, blocks access
    to protected endpoints for users who haven't enabled 2FA.

    **How It Works:**
    1. Runs on EVERY request after authentication
    2. Checks if user is authenticated
    3. Checks if path is exempt from enforcement
    4. Checks TwoFactorSettings.enforce_2fa_for_all_users
    5. Blocks users without 2FA from accessing protected endpoints

    **Where It's Registered:**
    config/settings/base.py -> MIDDLEWARE list
    """

    # Paths that are exempt from 2FA enforcement
    EXEMPT_PATHS = [
        '/auth/2fa/enable/',           # Allow users to enable 2FA
        '/auth/2fa/enable/verify/',    # Allow users to verify 2FA setup
        '/auth/2fa/status/',            # Allow users to check their 2FA status
        '/auth/2fa/verify/',            # Allow 2FA login verification
        '/auth/2fa/resend/',            # Allow resending 2FA codes
        '/auth/jwt/create/',            # Allow login endpoint
        '/auth/jwt/refresh/',           # Allow token refresh
        '/auth/jwt/verify/',            # Allow token verification
        '/auth/logout/',                # Allow logout
        '/auth/users/',                 # Allow user registration (POST only)
        '/auth/users/activation/',      # Allow email activation
        '/auth/users/resend_activation/',  # Allow resend activation
        '/auth/users/reset_password/',  # Allow password reset
        '/auth/users/reset_password_confirm/',  # Allow password reset confirm
        '/auth/google/',                # Allow OAuth login
        '/auth/google/callback/',       # Allow OAuth callback
        '/admin/',                      # Allow admin access
        '/api/schema/',                 # Allow API schema
        '/api/docs/',                   # Allow API docs
        '/api/redoc/',                  # Allow ReDoc
        '/accounts/',                   # Allow allauth URLs
    ]

    def __init__(self, get_response):
        """Initialize middleware."""
        self.get_response = get_response

    def __call__(self, request):
        """
        Process request and enforce 2FA if required.

        This method is called for EVERY HTTP request to the Django application.

        Args:
            request: HttpRequest object

        Returns:
            HttpResponse: Either the normal response or a 403 JSON error
        """

        # Step 1: Check if user is authenticated
        if not request.user.is_authenticated:
            # Not authenticated, let request pass (no enforcement for anonymous users)
            return self.get_response(request)

        # Step 2: Check if path is exempt from enforcement
        if self._is_path_exempt(request.path):
            # Exempt path (like /auth/2fa/enable/), let request pass
            return self.get_response(request)

        # Step 3: Get TwoFactorSettings to check global enforcement policy
        settings_obj = get_twofactor_settings()
        if not settings_obj:
            # Fallback if cached settings not available
            try:
                settings_obj = TwoFactorSettings.get_solo()
            except Exception as e:
                logger.error(f"Failed to retrieve TwoFactorSettings in middleware: {str(e)}")
                # If we can't get settings, let request pass (fail open for availability)
                return self.get_response(request)

        # Step 4: Check if global 2FA enforcement is enabled
        if not settings_obj.enforce_2fa_for_all_users:
            # Enforcement not enabled globally
            # Note: If user has opted into 2FA (is_2fa_enabled=True), they already
            # passed 2FA verification during login to get their JWT token.
            # The JWT token itself is proof they completed 2FA.
            return self.get_response(request)

        # Step 5: Global enforcement is ON - Check if user has 2FA enabled
        if request.user.is_2fa_enabled:
            # User has 2FA enabled and passed verification (proven by valid JWT token)
            return self.get_response(request)

        # Step 6: Global enforcement is ON but user hasn't enabled 2FA - BLOCK REQUEST
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
