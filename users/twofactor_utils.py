"""
Utility functions for two-factor authentication.

Provides code generation, validation, and email sending functionality.
"""

import secrets
import logging
from datetime import timedelta

from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone

from users.models import TwoFactorCode

logger = logging.getLogger(__name__)


def generate_2fa_code(user, settings_obj=None, verification_type='TWO_FACTOR'):
    """
    Generate a new 6-digit 2FA code for the specified user.

    Invalidates any previous unused codes for the user before generating
    a new one to ensure only one active code per user.

    Args:
        user: User instance to generate code for
        verification_type: Type of verification ('TWO_FACTOR')

    Returns:
        TwoFactorCode: The newly created code instance
    """
    # Invalidate any previous unused codes for this user with same verification type
    TwoFactorCode.objects.filter(
        user=user,
        is_used=False,
        verification_type=verification_type
    ).update(is_used=True)

    # Generate 6-digit numeric code using cryptographically secure random
    code_length = 6  # Always use 6 digits
    expiration_seconds = settings.TWOFACTOR_CODE_EXPIRATION_SECONDS

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


def send_2fa_code(user, code, preferred_2fa_method='None', verification_type='TWO_FACTOR'):
    """
    Send 2FA verification code to user via their preferred method.

    Args:
        user: User instance to send code to
        code: The 6-digit verification code string
        preferred_2fa_method: Delivery method ('EMAIL' or 'PHONE'). If None, uses user's preference or system default.
        verification_type: Type of verification to customize message content

    Returns:
        int: 1 on success, 0 on failure

    Raises:
        NotImplementedError: If PHONE method is requested (not yet implemented)
    """
    # Determine the delivery method
    if preferred_2fa_method is None:
        # Use user's preferred method if set, otherwise use system default
        preferred_2fa_method = user.get_effective_2fa_method()

    # Convert to uppercase to handle case variations
    preferred_2fa_method = preferred_2fa_method.upper()

    # Route to appropriate delivery method
    if preferred_2fa_method == 'EMAIL':
        return _send_2fa_code_via_email(user, code, verification_type)
    elif preferred_2fa_method == 'PHONE':
        raise NotImplementedError(
            "Phone 2FA delivery is not yet implemented. Please use EMAIL method."
        )
    else:
        logger.error(f"Unknown 2FA method: {preferred_2fa_method}. Defaulting to EMAIL.")
        return _send_2fa_code_via_email(user, code, verification_type)


def _send_2fa_code_via_email(user, code, verification_type='TWO_FACTOR'):
    """
    Send 2FA verification code to user's email.

    Internal implementation for email delivery.

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
    expiration_seconds = settings.TWOFACTOR_CODE_EXPIRATION_SECONDS
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

    from django.core.mail import EmailMultiAlternatives
    email_msg = EmailMultiAlternatives(
        subject=subject,
        body=message,
        from_email=from_email,
        to=[],  # 使用空列表，避免在 To 欄位顯示收件人
        bcc=recipient_list,  # 使用密件副本保護個資
    )
    return email_msg.send(fail_silently=False)
