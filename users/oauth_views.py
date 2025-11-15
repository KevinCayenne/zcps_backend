"""
Custom OAuth views for Google authentication.

Handles OAuth initiation and callback with JWT token generation.
"""

import logging
from django.shortcuts import redirect
from django.views import View
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from dj_rest_auth.registration.views import SocialLoginView, SocialConnectView
from drf_spectacular.utils import extend_schema, OpenApiResponse
from .oauth_adapters import (
    build_error_redirect_url,
    build_success_redirect_url,
    generate_jwt_tokens,
    generate_temporary_2fa_token
)
from .twofactor_utils import generate_2fa_code, send_2fa_code_email
from users.models import TwoFactorSettings

logger = logging.getLogger(__name__)


@extend_schema(
    tags=['Authentication'],
    summary='Initiate Google OAuth login (Browser redirect)',
    description="""
    **IMPORTANT: This endpoint requires a browser and cannot be tested directly in Swagger UI.**

    Initiates the Google OAuth 2.0 authentication flow.

    **How to Use:**
    1. Open this URL in a browser: `http://localhost:8000/auth/google/`
    2. User is redirected to Google's consent screen
    3. User authorizes the application
    4. User is redirected back to `/auth/google/callback/`
    5. Backend creates/links user account
    6. User is redirected to frontend with JWT tokens or temp_token

    **OAuth Flow:**
    ```
    User clicks "Sign in with Google"
    ↓
    Frontend redirects to: GET /auth/google/
    ↓
    Backend redirects to: Google OAuth consent screen
    ↓
    User authorizes application
    ↓
    Google redirects to: GET /auth/google/callback/?code=...
    ↓
    Backend processes authorization code
    ↓
    Backend redirects to frontend with tokens
    ```

    **Scopes Requested:**
    - `openid`: User identification
    - `profile`: Basic profile information
    - `email`: Email address

    **Redirect After Success:**
    - Without 2FA: `{FRONTEND_URL}/auth/callback?access=...&refresh=...`
    - With 2FA: `{FRONTEND_URL}/auth/callback?temp_token=...&requires_2fa=true`

    **Account Linking:**
    - If email exists: Google account is linked to existing user
    - If new email: New user account is created
    - Email is auto-verified for OAuth users

    **Frontend Integration:**
    See `/docs/google-oauth-frontend-integration.md` for complete guide.
    """,
    responses={
        302: OpenApiResponse(description='Redirect to Google OAuth consent screen'),
    }
)
class GoogleLogin(SocialLoginView):
    """
    Google OAuth login view.

    Initiates Google OAuth flow by redirecting to Google's consent screen.
    """
    adapter_class = GoogleOAuth2Adapter
    callback_url = None  # Will be set in get_callback_url
    client_class = OAuth2Client

    def get_callback_url(self, request, app):
        """Get the callback URL for OAuth."""
        # Use the current request to build absolute callback URL
        return request.build_absolute_uri('/auth/google/callback/')


class GoogleCallback(View):
    """
    Google OAuth callback view.

    Handles OAuth callback, creates/links user, generates JWT tokens,
    and redirects to frontend with tokens or temp_token based on 2FA enforcement.
    """

    def get(self, request):
        """Handle OAuth callback GET request."""
        try:
            # Check for OAuth errors (user denied access)
            if 'error' in request.GET:
                error = request.GET.get('error')
                if error == 'access_denied':
                    logger.info("User denied OAuth access")
                    return redirect(build_error_redirect_url(
                        'access_denied',
                        'You denied access to your Google account.'
                    ))
                else:
                    logger.error(f"OAuth error: {error}")
                    return redirect(build_error_redirect_url(
                        'oauth_error',
                        f'OAuth error: {error}'
                    ))

            # Process the OAuth callback using django-allauth
            from allauth.socialaccount.providers.google.views import oauth2_callback
            from allauth.socialaccount.helpers import complete_social_login
            from allauth.socialaccount.models import SocialLogin

            # Get the code from query parameters
            code = request.GET.get('code')
            if not code:
                logger.error("No authorization code in callback")
                return redirect(build_error_redirect_url(
                    'invalid_request',
                    'No authorization code provided.'
                ))

            # Exchange code for tokens and get user info
            adapter = GoogleOAuth2Adapter(request)
            app = adapter.get_provider().get_app(request)
            callback_url = request.build_absolute_uri('/auth/google/callback/')

            client = OAuth2Client(
                request,
                app.client_id,
                app.secret,
                adapter.access_token_method,
                adapter.access_token_url,
                callback_url,
                adapter.scope_delimiter,
                scope=adapter.get_provider().get_scope(request),
            )

            # Get access token
            token = client.get_access_token(code)
            access_token = token['access_token']

            # Complete social login (this will create/link user)
            login = adapter.complete_login(request, app, access_token, response=token)
            login.token = token

            # Process the login
            ret = complete_social_login(request, login)

            # Get the logged-in user
            if hasattr(login, 'account') and hasattr(login.account, 'user'):
                user = login.account.user
            elif hasattr(request, 'user') and request.user.is_authenticated:
                user = request.user
            else:
                logger.error("Could not retrieve user after OAuth")
                return redirect(build_error_redirect_url(
                    'server_error',
                    'An error occurred during authentication.'
                ))

            # Auto-verify email for OAuth users (trust Google's verification)
            extra_data = login.account.extra_data if hasattr(login, 'account') else {}
            if extra_data.get('email_verified', False):
                user.email_verified = True
                user.save(update_fields=['email_verified'])

            # Get TwoFactorSettings to check enforcement policy
            settings_obj = TwoFactorSettings.get_solo()

            # Check if 2FA enforcement is enabled AND user has 2FA enabled
            if settings_obj.enforce_2fa_for_all_users and user.is_2fa_enabled:
                # Generate and send 2FA code
                twofactor_code = generate_2fa_code(user, settings_obj, verification_type='TWO_FACTOR')
                send_2fa_code_email(user, twofactor_code.code, verification_type='TWO_FACTOR')

                # Generate temporary token for 2FA verification
                temp_token = generate_temporary_2fa_token(user)

                logger.info(f"OAuth user {user.email} requires 2FA verification")

                # Redirect to frontend with temp_token for 2FA flow
                from urllib.parse import urlencode
                from django.conf import settings
                base_url = settings.GOOGLE_OAUTH_SUCCESS_REDIRECT_URL
                params = urlencode({
                    'temp_token': temp_token,
                    'requires_2fa': 'true',
                    'expires_at': twofactor_code.expires_at.isoformat()
                })
                return redirect(f"{base_url}?{params}")

            # No 2FA required - generate standard JWT tokens
            access_token_jwt, refresh_token_jwt = generate_jwt_tokens(user)

            logger.info(f"OAuth successful for user: {user.email}")

            # Redirect to frontend with full JWT tokens
            return redirect(build_success_redirect_url(access_token_jwt, refresh_token_jwt))

        except Exception as e:
            logger.error(f"Error in Google OAuth callback: {str(e)}", exc_info=True)
            return redirect(build_error_redirect_url(
                'server_error',
                'An unexpected error occurred during authentication.'
            ))
