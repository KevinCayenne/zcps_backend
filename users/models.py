"""
Custom User model for Django boilerplate.

Extends Django's AbstractUser to add custom fields and functionality.
"""

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from solo.models import SingletonModel


class TwoFactorSettings(SingletonModel):
    """
    Singleton model for system-wide Two-Factor Authentication configuration.

    Only one instance of this model can exist in the database.
    Provides runtime-configurable 2FA settings through admin interface.
    """

    enforce_2fa_for_all_users = models.BooleanField(
        default=False,
        help_text='When enabled, all users must enable 2FA to access the system'
    )

    default_2fa_method = models.CharField(
        max_length=20,
        choices=[
            ('EMAIL', 'Email'),
            ('PHONE', 'Phone (coming soon)'),
        ],
        default='EMAIL',
        help_text='Default 2FA method for users who have not set a preference'
    )

    code_expiration_seconds = models.PositiveIntegerField(
        default=600,
        help_text='Number of seconds before a 2FA code expires (default: 600 = 10 minutes)'
    )

    max_failed_attempts = models.PositiveIntegerField(
        default=5,
        help_text='Maximum number of failed verification attempts before code is locked'
    )

    temporary_token_lifetime_minutes = models.PositiveIntegerField(
        default=10,
        help_text='Lifetime of temporary 2FA tokens in minutes (used during login flow)'
    )

    class Meta:
        verbose_name = 'Two-Factor Authentication Settings'
        verbose_name_plural = 'Two-Factor Authentication Settings'

    def __str__(self):
        """Return string representation of settings."""
        return "Two-Factor Authentication Settings"


class User(AbstractUser):
    """
    Custom User model extending AbstractUser.

    Adds phone_number field and makes email required and unique.
    Includes created_at and updated_at timestamps for auditing.
    Supports Google OAuth with google_id and profile_picture_url fields.
    Supports email-based two-factor authentication with tracking fields.
    """

    # Override email to make it required and unique
    email = models.EmailField(
        'email address',
        unique=True,
        blank=False,
        error_messages={
            'unique': 'A user with this email already exists.',
        }
    )

    # Add phone_number field supporting international format
    phone_number = models.CharField(
        max_length=17,
        blank=True,
        null=True,
        help_text='Phone number in international format (e.g., +1 234 5678901)'
    )

    # OAuth fields
    google_id = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        unique=True,
        db_index=True,
        help_text='Google OAuth user ID'
    )

    profile_picture_url = models.URLField(
        blank=True,
        null=True,
        help_text='URL to user profile picture from OAuth provider'
    )

    # Email verification field
    email_verified = models.BooleanField(
        default=False,
        help_text='Whether user email has been verified'
    )

    # Two-Factor Authentication fields
    is_2fa_enabled = models.BooleanField(
        default=False,
        help_text='Whether user has enabled two-factor authentication'
    )

    twofa_setup_date = models.DateTimeField(
        blank=True,
        null=True,
        help_text='Timestamp when user first enabled 2FA'
    )

    last_2fa_verification = models.DateTimeField(
        blank=True,
        null=True,
        help_text='Timestamp of last successful 2FA verification for audit trails'
    )

    # New 2FA method selection fields
    preferred_2fa_method = models.CharField(
        max_length=20,
        choices=[
            ('EMAIL', 'Email'),
            ('PHONE', 'Phone'),
        ],
        blank=True,
        null=True,
        help_text='User preferred 2FA method (null uses system default)'
    )

    phone_number_verified = models.BooleanField(
        default=False,
        help_text='Whether user phone number has been verified for 2FA'
    )

    # Add timestamp fields for auditing
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'user'
        verbose_name_plural = 'users'
        ordering = ['-created_at']

    def __str__(self):
        """Return string representation of user."""
        return self.email if self.email else self.username

    def get_effective_2fa_method(self):
        """
        Get the effective 2FA method for this user.

        Returns user's preferred method if set, otherwise returns system default.

        Returns:
            str: 'EMAIL' or 'PHONE'
        """
        if self.preferred_2fa_method:
            return self.preferred_2fa_method

        # Get system default from TwoFactorSettings
        try:
            settings_obj = TwoFactorSettings.get_solo()
            return settings_obj.default_2fa_method
        except Exception:
            # Fallback to EMAIL if settings not available
            return 'EMAIL'


class TwoFactorCode(models.Model):
    """
    Model for storing two-factor authentication verification codes.

    Codes are time-limited and single-use for security.
    Tracks failed verification attempts for brute force protection.
    Supports different verification types (2FA login vs email verification).
    """

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='twofactor_codes',
        help_text='User this verification code belongs to'
    )

    code = models.CharField(
        max_length=6,
        help_text='6-digit numeric verification code'
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text='Timestamp when code was generated'
    )

    expires_at = models.DateTimeField(
        help_text='Timestamp when code expires',
        db_index=True
    )

    is_used = models.BooleanField(
        default=False,
        help_text='Whether code has been used successfully'
    )

    failed_attempts = models.IntegerField(
        default=0,
        help_text='Number of failed verification attempts for this code'
    )

    verification_type = models.CharField(
        max_length=20,
        choices=[
            ('TWO_FACTOR', 'Two-Factor Authentication'),
        ],
        default='TWO_FACTOR',
        help_text='Type of verification this code is used for'
    )

    class Meta:
        verbose_name = 'two-factor code'
        verbose_name_plural = 'two-factor codes'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'expires_at']),
        ]

    def __str__(self):
        """Return string representation of code."""
        return f"2FA code for {self.user.email} (expires {self.expires_at})"

    def is_valid(self, max_attempts=5):
        """
        Check if code is valid for verification.

        A code is valid if:
        - It has not expired
        - It has not been used
        - Failed attempts are under the max threshold

        Args:
            max_attempts: Maximum allowed failed attempts (default: 5)

        Returns:
            bool: True if code is valid, False otherwise
        """
        return (
            not self.is_used
            and self.expires_at > timezone.now()
            and self.failed_attempts < max_attempts
        )
