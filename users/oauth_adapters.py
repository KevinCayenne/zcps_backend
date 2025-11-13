"""
Custom OAuth adapters for handling Google OAuth flow.

Implements account linking and JWT token generation.
"""

import logging
from urllib.parse import urlencode
from datetime import timedelta
from django.conf import settings
from django.shortcuts import redirect
from django.utils import timezone
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.socialaccount.models import SocialAccount
from rest_framework_simplejwt.tokens import RefreshToken

logger = logging.getLogger(__name__)


class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    """
    Custom social account adapter for Google OAuth.

    Handles account linking by email matching and stores OAuth data.
    """

    def pre_social_login(self, request, sociallogin):
        """
        Handle account linking before social login.

        If a user with the same email exists, link the social account to that user.
        """
        if sociallogin.is_existing:
            return

        try:
            email = sociallogin.account.extra_data.get('email', '').lower()
            if not email:
                return

            # Try to find existing user by email
            from django.contrib.auth import get_user_model
            User = get_user_model()

            try:
                existing_user = User.objects.get(email__iexact=email)

                # Link the social account to the existing user
                sociallogin.connect(request, existing_user)

                # Update OAuth fields on the user
                self._update_user_oauth_fields(existing_user, sociallogin)

                logger.info(f"Linked Google account to existing user: {email}")
            except User.DoesNotExist:
                # No existing user, will create new one
                pass

        except Exception as e:
            logger.error(f"Error during pre_social_login: {str(e)}")

    def populate_user(self, request, sociallogin, data):
        """
        Populate user model fields from social account data.

        Called when creating a new user via social login.
        """
        user = super().populate_user(request, sociallogin, data)

        # Set unusable password for OAuth-created users
        user.set_unusable_password()

        # Extract additional data from Google profile
        extra_data = sociallogin.account.extra_data

        # Get first and last name
        if 'given_name' in extra_data:
            user.first_name = extra_data['given_name'][:30]  # Limit to field max_length

        if 'family_name' in extra_data:
            user.last_name = extra_data['family_name'][:150]  # Limit to field max_length

        return user

    def save_user(self, request, sociallogin, form=None):
        """
        Save user and update OAuth-specific fields.
        """
        user = super().save_user(request, sociallogin, form)

        # Update OAuth fields after user is saved
        self._update_user_oauth_fields(user, sociallogin)

        logger.info(f"Created new OAuth user: {user.email}")

        return user

    def _update_user_oauth_fields(self, user, sociallogin):
        """Update user's OAuth fields from social login data."""
        try:
            extra_data = sociallogin.account.extra_data

            # Update google_id
            if 'id' in extra_data or 'sub' in extra_data:
                user.google_id = extra_data.get('id') or extra_data.get('sub')

            # Update profile_picture_url
            if 'picture' in extra_data:
                user.profile_picture_url = extra_data['picture']

            user.save(update_fields=['google_id', 'profile_picture_url'])
        except Exception as e:
            logger.error(f"Error updating OAuth fields: {str(e)}")


def build_error_redirect_url(error_type, error_message):
    """
    Build error redirect URL with query parameters.

    Args:
        error_type: Type of error (e.g., 'access_denied', 'invalid_credentials')
        error_message: Human-readable error message

    Returns:
        Full redirect URL with error parameters
    """
    base_url = settings.GOOGLE_OAUTH_ERROR_REDIRECT_URL
    params = urlencode({
        'error_type': error_type,
        'error_message': error_message
    })
    return f"{base_url}?{params}"


def build_success_redirect_url(access_token, refresh_token):
    """
    Build success redirect URL with JWT tokens as query parameters.

    Args:
        access_token: JWT access token
        refresh_token: JWT refresh token

    Returns:
        Full redirect URL with token parameters
    """
    base_url = settings.GOOGLE_OAUTH_SUCCESS_REDIRECT_URL
    params = urlencode({
        'access': access_token,
        'refresh': refresh_token
    })
    return f"{base_url}?{params}"


def generate_jwt_tokens(user):
    """
    Generate JWT access and refresh tokens for user.

    Args:
        user: User instance

    Returns:
        Tuple of (access_token, refresh_token)
    """
    refresh = RefreshToken.for_user(user)
    return str(refresh.access_token), str(refresh)


def generate_temporary_2fa_token(user):
    """
    Generate temporary JWT token for 2FA verification flow.

    Token is short-lived (10 minutes by default) and includes custom claims
    to indicate it's a temporary 2FA token.

    Args:
        user: User instance

    Returns:
        str: Temporary JWT token string
    """
    refresh = RefreshToken.for_user(user)

    # Set custom claim to indicate this is a temporary 2FA token
    refresh['temp_2fa'] = True
    refresh['user_id'] = user.id

    # Set short expiration time for temporary token
    temp_lifetime_minutes = getattr(settings, 'TWOFACTOR_TEMPORARY_TOKEN_LIFETIME', 10)
    refresh.access_token.set_exp(lifetime=timedelta(minutes=temp_lifetime_minutes))

    return str(refresh.access_token)
