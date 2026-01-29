"""
Custom User model for Django boilerplate.

Extends Django's AbstractUser to add custom fields and functionality.
"""

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from users.enums import UserRole, InformationSource, OccupationCategory, Gender


class User(AbstractUser):
    """
    Custom User model extending AbstractUser.

    Adds phone_number field and makes email required and unique.
    Includes created_at and updated_at timestamps for auditing.
    Supports Google OAuth with google_id and profile_picture_url fields.
    Supports email-based two-factor authentication with tracking fields.
    Includes role-based permission system with role field.
    """

    # Override email to make it required and unique
    email = models.EmailField(
        verbose_name=_("Email"),
        unique=True,
        blank=False,
        error_messages={
            "unique": "此電子郵件已被使用。",
        },
    )

    # Add phone_number field supporting international format
    phone_number = models.CharField(
        verbose_name=_("手機號碼"),
        max_length=17,
        blank=True,
        null=True,
        unique=True,
        db_index=True,
        help_text="Phone number in international format (e.g., +1 234 5678901)",
        error_messages={
            "unique": "此手機號碼已被使用。",
            "invalid": "無效的手機號碼格式。",
            "max_length": "手機號碼長度不能超過 {max_length} 個字元。",
        },
    )

    # OAuth fields
    google_id = models.CharField(
        verbose_name=_("Google ID"),
        max_length=255,
        blank=True,
        null=True,
        unique=True,
        db_index=True,
        help_text="Google OAuth user ID",
        error_messages={
            "unique": "此 Google ID 已被使用。",
        },
    )

    profile_picture_url = models.URLField(
        verbose_name=_("大頭貼網址"),
        blank=True,
        null=True,
        help_text="URL to user profile picture from OAuth provider",
        error_messages={
            "invalid": "無效的大頭貼網址格式。",
        },
    )

    # Email verification field
    email_verified = models.BooleanField(
        verbose_name=_("Email 驗證"),
        default=False,
        help_text="Whether user email has been verified",
        error_messages={
            "invalid": "無效的 Email 驗證狀態。",
        },
    )

    # Two-Factor Authentication fields
    is_2fa_enabled = models.BooleanField(
        verbose_name=_("是否啟用兩步驟驗證"),
        default=False,
        help_text="Whether user has enabled two-factor authentication",
        error_messages={
            "invalid": "無效的兩步驟驗證狀態。",
        },
    )

    twofa_setup_date = models.DateTimeField(
        verbose_name=_("兩步驟驗證設定日期"),
        blank=True,
        null=True,
        help_text="Timestamp when user first enabled 2FA",
    )

    last_2fa_verification = models.DateTimeField(
        verbose_name=_("最後兩步驟驗證日期"),
        blank=True,
        null=True,
        help_text="Timestamp of last successful 2FA verification for audit trails",
    )

    # New 2FA method selection fields
    preferred_2fa_method = models.CharField(
        verbose_name=_("偏好兩步驟驗證方式"),
        max_length=20,
        choices=[
            ("EMAIL", "Email"),
            ("PHONE", "Phone"),
        ],
        default="EMAIL",
        help_text="User preferred 2FA method (default is EMAIL)",
    )

    phone_number_verified = models.BooleanField(
        verbose_name=_("手機號碼驗證"),
        default=False,
        help_text="Whether user phone number has been verified for 2FA",
    )

    # Role/Permission fields
    role = models.CharField(
        verbose_name=_("權限角色"),
        max_length=20,
        choices=UserRole.choices,
        default=UserRole.CLIENT,
        help_text="User role for permission management",
    )

    information_source = models.CharField(
        max_length=20,
        choices=InformationSource.CHOICES,
        verbose_name=_("資訊來源"),
        help_text=_("怎麼知道LBV認證活動資訊"),
    )

    residence_county = models.CharField(
        verbose_name=_("居住地縣市"),
        max_length=20,
        blank=True,
        null=True,
        help_text=_("用戶居住地縣市"),
    )

    # 職業類別（註冊時填寫）
    occupation_category = models.CharField(
        verbose_name=_("職業類別"),
        max_length=50,  # 增加長度以支持更長的選項值
        choices=OccupationCategory.CHOICES,
        default=OccupationCategory.OTHER,
        help_text=_("申請人的職業類別"),
    )

    # 自定義職業類別（當 occupation_category 為 CUSTOM 時使用）
    occupation_category_custom = models.CharField(
        verbose_name=_("自定義職業類別"),
        max_length=100,
        blank=True,
        null=True,
        help_text=_("當選擇「其他（請填寫）」時，可在此填寫自定義職業類別"),
    )

    # 性別
    gender = models.CharField(
        verbose_name=_("性別"),
        max_length=10,
        choices=Gender.CHOICES,
        blank=True,
        null=True,
        help_text=_("用戶性別"),
    )

    # 生日
    birth_date = models.DateField(
        verbose_name=_("生日"),
        blank=True,
        null=True,
        help_text=_("用戶生日"),
    )

    # 是否同意隱私權條款
    privacy_policy_accepted = models.BooleanField(
        verbose_name=_("是否同意隱私權條款"),
        default=False,
        help_text=_("用戶是否同意隱私權條款"),
    )

    # Add timestamp fields for auditing
    created_at = models.DateTimeField(verbose_name=_("建立日期"), auto_now_add=True)
    updated_at = models.DateTimeField(verbose_name=_("更新日期"), auto_now=True)
    cert_record_group_id = models.IntegerField(
        verbose_name=_("證書群組 ID"),
        blank=True,
        null=True,
        help_text=_("證書群組 ID"),
        db_index=True,
    )

    class Meta:
        verbose_name = _("使用者")
        verbose_name_plural = _("使用者")
        ordering = ["-created_at"]

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

        # Get system default from settings
        return settings.TWOFACTOR_DEFAULT_METHOD


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
        related_name="twofactor_codes",
        help_text="User this verification code belongs to",
    )

    code = models.CharField(
        verbose_name=_("驗證碼"),
        max_length=6,
        help_text="6-digit numeric verification code",
    )

    created_at = models.DateTimeField(
        verbose_name=_("建立日期"),
        auto_now_add=True,
        help_text="Timestamp when code was generated",
    )

    expires_at = models.DateTimeField(
        verbose_name=_("到期日期"),
        help_text="Timestamp when code expires",
        db_index=True,
    )

    is_used = models.BooleanField(
        verbose_name=_("是否已使用"),
        default=False,
        help_text="Whether code has been used successfully",
    )

    failed_attempts = models.IntegerField(
        verbose_name=_("失敗驗證次數"),
        default=0,
        help_text="Number of failed verification attempts for this code",
    )

    verification_type = models.CharField(
        verbose_name=_("驗證類型"),
        max_length=20,
        choices=[
            ("TWO_FACTOR", "Two-Factor Authentication"),
        ],
        default="TWO_FACTOR",
        help_text="Type of verification this code is used for",
    )

    class Meta:
        verbose_name = _("多因子驗證碼")
        verbose_name_plural = _("多因子驗證碼")
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "expires_at"]),
        ]

    def __str__(self):
        """Return string representation of code."""
        return f"{_('多因子驗證碼')} {self.user.email} ({_('expires')}           {self.expires_at})"

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


class EmailVerificationOTP(models.Model):
    """
    註冊前的 Email OTP 驗證模型

    用於在用戶註冊前驗證 email 是否有效。
    """

    email = models.EmailField(
        verbose_name=_("Email 地址"), help_text="要驗證的 email 地址", db_index=True
    )

    code = models.CharField(
        verbose_name=_("驗證碼"), max_length=6, help_text="6 位數驗證碼"
    )

    created_at = models.DateTimeField(
        verbose_name=_("建立時間"), auto_now_add=True, help_text="驗證碼生成時間"
    )

    expires_at = models.DateTimeField(
        verbose_name=_("過期時間"), help_text="驗證碼過期時間", db_index=True
    )

    is_used = models.BooleanField(
        verbose_name=_("是否已使用"),
        default=False,
        help_text="驗證碼是否已被使用",
        db_index=True,
    )

    failed_attempts = models.IntegerField(
        verbose_name=_("失敗驗證次數"),
        default=0,
        help_text="失敗驗證次數（超過 5 次需重新發送）",
    )

    class Meta:
        verbose_name = _("Email 驗證 OTP")
        verbose_name_plural = _("Email 驗證 OTP")
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["email", "is_used"]),
            models.Index(fields=["email", "expires_at"]),
        ]

    def __str__(self):
        return f"{self.email} - {self.code}"

    def is_valid(self):
        """
        檢查驗證碼是否有效（未使用且未過期）
        """
        from django.utils import timezone

        return (
            not self.is_used
            and timezone.now() <= self.expires_at
            and self.failed_attempts < 5
        )
