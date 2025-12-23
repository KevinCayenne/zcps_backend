"""
Middleware for Two-Factor Authentication enforcement and temporary token restriction.

Blocks authenticated users from accessing protected endpoints when 2FA is enforced
but the user hasn't enabled 2FA. Also restricts temporary 2FA tokens to specific endpoints.
"""

import logging
from django.conf import settings
from django.http import JsonResponse
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

logger = logging.getLogger(__name__)


class TwoFactorEnforcementMiddleware:
    """
    Middleware to enforce 2FA requirement for all authenticated users.

    When settings.TWOFACTOR_ENFORCE_FOR_ALL_USERS is True, blocks access
    to protected endpoints for users who haven't enabled 2FA.

    **How It Works:**
    1. Runs on EVERY request after authentication
    2. Checks if user is authenticated
    3. Checks if path is exempt from enforcement
    4. Checks TWOFACTOR_CONFIG.enforce_2fa_for_all_users
    5. Blocks users without 2FA from accessing protected endpoints

    **Where It's Registered:**
    config/settings/base.py -> MIDDLEWARE list
    """

    # Paths that are exempt from 2FA enforcement
    EXEMPT_PATHS = [
        "/auth/2fa/enable/",  # Allow users to enable 2FA
        "/auth/2fa/enable/verify/",  # Allow users to verify 2FA setup
        "/auth/2fa/status/",  # Allow users to check their 2FA status
        "/auth/2fa/verify/",  # Allow 2FA login verification
        "/auth/2fa/resend/",  # Allow resending 2FA codes
        "/auth/jwt/create/",  # Allow login endpoint
        "/auth/jwt/refresh/",  # Allow token refresh
        "/auth/jwt/verify/",  # Allow token verification
        "/auth/logout/",  # Allow logout
        "/auth/users/",  # Allow user registration (POST only)
        "/auth/users/activation/",  # Allow email activation
        "/auth/users/resend_activation/",  # Allow resend activation
        "/auth/users/reset_password/",  # Allow password reset
        "/auth/users/reset_password_confirm/",  # Allow password reset confirm
        "/auth/google/",  # Allow OAuth login
        "/auth/google/callback/",  # Allow OAuth callback
        "/admin/",  # Allow admin access
        "/api/schema/",  # Allow API schema
        "/api/docs/",  # Allow API docs
        "/api/redoc/",  # Allow ReDoc
        "/accounts/",  # Allow allauth URLs
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

        # Step 3: Check if global 2FA enforcement is enabled
        if not settings.TWOFACTOR_ENFORCE_FOR_ALL_USERS:
            # Enforcement not enabled globally
            # Note: If user has opted into 2FA (is_2fa_enabled=True), they already
            # passed 2FA verification during login to get their JWT token.
            # The JWT token itself is proof they completed 2FA.
            return self.get_response(request)

        # Step 4: Global enforcement is ON - Check if user has 2FA enabled
        if request.user.is_2fa_enabled:
            # User has 2FA enabled and passed verification (proven by valid JWT token)
            return self.get_response(request)

        # Step 5: Global enforcement is ON but user hasn't enabled 2FA - BLOCK REQUEST
        logger.warning(
            f"2FA enforcement blocked user {request.user.id} ({request.user.email}) "
            f"from accessing {request.path}"
        )

        return JsonResponse(
            {
                "error": "Two-factor authentication is required. Please enable 2FA at /auth/2fa/enable/",
                "required_action": "enable_2fa",
                "endpoint": "/auth/2fa/enable/",
            },
            status=403,
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


class TemporaryTokenRestrictionMiddleware:
    """
    Middleware to restrict temporary 2FA tokens to specific endpoints.

    Temporary 2FA tokens should ONLY be valid for:
    - /auth/2fa/verify/ - To complete 2FA verification during login
    - /auth/2fa/resend/ - To resend 2FA code during login
    - /auth/2fa/enable/ - To enable 2FA (when enforcement requires setup)
    - /auth/2fa/enable/verify/ - To verify 2FA setup
    - /auth/2fa/status/ - To check 2FA status

    Using a temporary token on any other endpoint will result in 403 Forbidden.

    **How It Works:**
    1. Runs on EVERY request after authentication
    2. Checks if request has an Authorization header with a JWT token
    3. Decodes the token to check for 'temp_2fa' claim
    4. If temp_2fa claim exists, validates that path is allowed
    5. Blocks temporary tokens from accessing non-2FA endpoints

    **Where It's Registered:**
    config/settings/base.py -> MIDDLEWARE list (after authentication middleware)
    """

    # Paths that temporary 2FA tokens are allowed to access
    ALLOWED_PATHS = [
        "/auth/2fa/verify/",  # Complete 2FA verification during login
        "/auth/2fa/resend/",  # Resend 2FA code during login
        "/auth/2fa/enable/",  # Enable 2FA (for setup when enforcement is enabled)
        "/auth/2fa/enable/verify/",  # Verify 2FA setup code
        "/auth/2fa/status/",  # Check 2FA status
    ]

    def __init__(self, get_response):
        """Initialize middleware."""
        self.get_response = get_response

    def __call__(self, request):
        """
        Process request and block temporary tokens from unauthorized endpoints.

        Args:
            request: HttpRequest object

        Returns:
            HttpResponse: Either the normal response or a 403 JSON error
        """

        # Step 1: Check if there's an Authorization header
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if not auth_header.startswith("Bearer "):
            # No JWT token in request, let it pass
            return self.get_response(request)

        # Step 2: Extract token from Authorization header
        try:
            token_string = auth_header.split(" ")[1]
        except IndexError:
            # Malformed Authorization header, let DRF handle it
            return self.get_response(request)

        # Step 3: Decode token to check for temp_2fa claim
        try:
            token = UntypedToken(token_string)
            is_temp_token = token.get("temp_2fa", False)
        except (InvalidToken, TokenError):
            # Invalid token, let DRF authentication handle it
            return self.get_response(request)

        # Step 4: If not a temporary token, allow request
        if not is_temp_token:
            return self.get_response(request)

        # Step 5: This IS a temporary token - check if path is allowed
        if self._is_path_allowed(request.path):
            # Allowed path for temporary tokens
            return self.get_response(request)

        # Step 6: Temporary token used on unauthorized endpoint - BLOCK REQUEST
        logger.warning(
            f"Temporary 2FA token blocked from accessing {request.path}. "
            f"Temp tokens are only valid for {', '.join(self.ALLOWED_PATHS)}"
        )

        return JsonResponse(
            {
                "error": "This temporary token can only be used for 2FA verification endpoints.",
                "allowed_endpoints": self.ALLOWED_PATHS,
                "detail": "Please complete 2FA verification at /auth/2fa/verify/ to obtain full access tokens.",
            },
            status=403,
        )

    def _is_path_allowed(self, path):
        """
        Check if the given path is allowed for temporary tokens.

        Args:
            path: Request path to check

        Returns:
            bool: True if path is allowed, False otherwise
        """
        for allowed_path in self.ALLOWED_PATHS:
            if path.startswith(allowed_path):
                return True
        return False
