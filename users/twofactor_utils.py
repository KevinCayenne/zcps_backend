"""
Utility functions for two-factor authentication.

Provides code generation, validation, and email sending functionality.
"""

import secrets
import warnings
import logging
from datetime import timedelta
from functools import lru_cache

from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone

from users.models import TwoFactorCode

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def get_twofactor_settings():
    """
    Get TwoFactorSettings singleton instance with caching.

    Returns cached settings object for performance.
    Logs error if settings not found (should never happen after migration).

    Returns:
        TwoFactorSettings: The singleton settings instance
    """
    from users.models import TwoFactorSettings
    try:
        return TwoFactorSettings.get_solo()
    except Exception as e:
        logger.error(f"Failed to retrieve TwoFactorSettings: {str(e)}")
        # Return None and let calling code handle fallback
        return None


def generate_2fa_code(user, settings_obj=None, verification_type='TWO_FACTOR'):
    """
    Generate a new 6-digit 2FA code for the specified user.

    Invalidates any previous unused codes for the user before generating
    a new one to ensure only one active code per user.

    Args:
        user: User instance to generate code for
        settings_obj: TwoFactorSettings instance (defaults to singleton)
        verification_type: Type of verification ('TWO_FACTOR')

    Returns:
        TwoFactorCode: The newly created code instance
    """
    # Get settings object if not provided
    if settings_obj is None:
        settings_obj = get_twofactor_settings()

    # Invalidate any previous unused codes for this user with same verification type
    TwoFactorCode.objects.filter(
        user=user,
        is_used=False,
        verification_type=verification_type
    ).update(is_used=True)

    # Generate 6-digit numeric code using cryptographically secure random
    if settings_obj:
        code_length = 6  # Always use 6 digits
        expiration_seconds = settings_obj.code_expiration_seconds
    else:
        # Fallback to Django settings with deprecation warning
        warnings.warn(
            "TwoFactorSettings not found. Using deprecated Django settings. "
            "Please ensure migrations have been run.",
            DeprecationWarning,
            stacklevel=2
        )
        code_length = getattr(settings, 'TWOFACTOR_CODE_LENGTH', 6)
        expiration_seconds = getattr(settings, 'TWOFACTOR_CODE_EXPIRATION', 600)

    code = ''.join([str(secrets.randbelow(10)) for _ in range(code_length)])

    # Calculate expiration time
    expires_at = timezone.now() + timedelta(seconds=expiration_seconds)

    # Create and return new code
    twofactor_code = TwoFactorCode.objects.create(
        user=user,
        code=code,
        expires_at=expires_at,
        verification_type=verification_type
    )

    return twofactor_code


def send_2fa_code_email(user, code, verification_type='TWO_FACTOR'):
    """
    Send 2FA verification code to user's email.

    Args:
        user: User instance to send code to
        code: The 6-digit verification code string
        verification_type: Type of verification to customize email content

    Returns:
        int: Number of emails sent (1 on success, 0 on failure)
    """
    # Customize subject and message based on verification type
    subject = 'Your Two-Factor Authentication Code'
    intro_text = 'Your two-factor authentication code is:'
    purpose_text = 'two-factor authentication'

    # Get expiration time in minutes for display
    settings_obj = get_twofactor_settings()
    if settings_obj:
        expiration_seconds = settings_obj.code_expiration_seconds
    else:
        # Fallback with deprecation warning
        warnings.warn(
            "TWOFACTOR_CODE_EXPIRATION setting is deprecated. Use TwoFactorSettings model.",
            DeprecationWarning,
            stacklevel=2
        )
        expiration_seconds = getattr(settings, 'TWOFACTOR_CODE_EXPIRATION', 600)

    expiration_minutes = expiration_seconds // 60

    message = f"""Hi {user.first_name or user.username},

{intro_text}

{code}

This code will expire in {expiration_minutes} minutes.

If you didn't request this code, please ignore this email or contact support if you have concerns about your account security.

Thank you,
The Team
"""

    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [user.email]

    return send_mail(
        subject,
        message,
        from_email,
        recipient_list,
        fail_silently=False,
    )
