"""
Custom OAuth views for Google authentication.

Handles OAuth initiation and callback with JWT token generation.
"""

import logging
from django.shortcuts import redirect
from django.http import HttpResponseRedirect
from django.views import View
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from allauth.socialaccount.providers.oauth2.views import OAuth2LoginView
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


# Create Google OAuth login view using django-allauth's OAuth2LoginView
# This handles the GET /auth/google/ endpoint that redirects to Google's consent screen
oauth_login = OAuth2LoginView.adapter_view(GoogleOAuth2Adapter)


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
                    return HttpResponseRedirect(build_error_redirect_url(
                        'access_denied',
                        'You denied access to your Google account.'
                    ))
                else:
                    logger.error(f"OAuth error: {error}")
                    return HttpResponseRedirect(build_error_redirect_url(
                        'oauth_error',
                        f'OAuth error: {error}'
                    ))

            # Process the OAuth callback using django-allauth
            from allauth.socialaccount.helpers import complete_social_login
            import requests

            # Get the code from query parameters
            code = request.GET.get('code')
            if not code:
                logger.error("No authorization code in callback")
                return HttpResponseRedirect(build_error_redirect_url(
                    'invalid_request',
                    'No authorization code provided.'
                ))

            # Get the Google OAuth app credentials from allauth
            adapter = GoogleOAuth2Adapter(request)
            provider = adapter.get_provider()
            app = provider.app

            # Exchange authorization code for access token using Google's token endpoint
            token_url = 'https://oauth2.googleapis.com/token'
            token_data = {
                'client_id': app.client_id,
                'client_secret': app.secret,
                'code': code,
                'grant_type': 'authorization_code',
                'redirect_uri': request.build_absolute_uri('/auth/google/callback/'),
            }

            token_response = requests.post(token_url, data=token_data)
            if token_response.status_code != 200:
                logger.error(f"Token exchange failed: {token_response.text}")
                return HttpResponseRedirect(build_error_redirect_url(
                    'token_exchange_failed',
                    'Failed to exchange authorization code for tokens.'
                ))

            token = token_response.json()

            # Complete the login with user data
            login = adapter.complete_login(request, app, token, response=token)

            # Process the social login (creates/updates user)
            complete_social_login(request, login)

            # Get the logged-in user
            if hasattr(login, 'account') and hasattr(login.account, 'user'):
                user = login.account.user
            elif hasattr(request, 'user') and request.user.is_authenticated:
                user = request.user
            else:
                logger.error("Could not retrieve user after OAuth")
                return HttpResponseRedirect(build_error_redirect_url(
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
                return HttpResponseRedirect(f"{base_url}?{params}")

            # No 2FA required - generate standard JWT tokens
            access_token_jwt, refresh_token_jwt = generate_jwt_tokens(user)

            logger.info(f"OAuth successful for user: {user.email}")

            # Redirect to frontend with full JWT tokens
            return HttpResponseRedirect(build_success_redirect_url(access_token_jwt, refresh_token_jwt))

        except Exception as e:
            logger.error(f"Error in Google OAuth callback: {str(e)}", exc_info=True)
            return HttpResponseRedirect(build_error_redirect_url(
                'server_error',
                'An unexpected error occurred during authentication.'
            ))
