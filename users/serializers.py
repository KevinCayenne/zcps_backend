"""
Serializers for User model and authentication.

Provides custom serializers for user registration and profile management.
"""

from rest_framework import serializers
from django.contrib.auth import get_user_model
from djoser.serializers import UserCreateSerializer as DjoserUserCreateSerializer
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for User model (read operations).

    Used for displaying user profile information.
    Excludes password and other sensitive fields.
    """

    class Meta:
        model = User
        fields = (
            'id',
            'username',
            'email',
            'first_name',
            'last_name',
            'phone_number',
            'profile_picture_url',
            'email_verified',
            'phone_number_verified',
            'is_2fa_enabled',
            'twofa_setup_date',
            'last_2fa_verification',
            'preferred_2fa_method',
            'role',
            'is_active',
            'last_login',
            'date_joined',
            'created_at',
            'updated_at',
        )
        read_only_fields = (
            'id', 
            'created_at',
            'updated_at',
            'username',
            'email_verified',
            'phone_number_verified',
            'twofa_setup_date',
            'is_2fa_enabled',
            'last_2fa_verification',
            'preferred_2fa_method',
            'role',
            'is_active',
            'last_login',
            'date_joined',
        )


class ClientUserSerializer(serializers.ModelSerializer):
    """
    Serializer for User model (read operations).

    Used for displaying user profile information.
    Excludes password and other sensitive fields.
    """

    class Meta:
        model = User
        fields = (
            'id',
            'username',
            'email',
            'first_name',
            'last_name',
            'phone_number',
            'profile_picture_url',
            'email_verified',
            'phone_number_verified',
            'is_2fa_enabled',
            'twofa_setup_date',
            'last_2fa_verification',
            'preferred_2fa_method',
            'role',
            'is_active',
            'last_login',
            'date_joined',
            'created_at',
            'updated_at',
        )
        read_only_fields = (
            'id', 
            'created_at',
            'updated_at',
            'username',
            'email_verified',
            'phone_number_verified',
            'twofa_setup_date',
            'is_2fa_enabled',
            'last_2fa_verification',
            'role',
            'is_active',
            'last_login',
            'date_joined',
        )


class UserCreateSerializer(DjoserUserCreateSerializer):
    """
    Serializer for user registration (create operation).

    Extends Djoser's UserCreateSerializer to add phone_number field.
    Ensures password is write-only and validates all fields.
    """

    phone_number = serializers.CharField(
        max_length=17,
        required=False,
        allow_blank=True,
        help_text='Phone number in international format (e.g., +1 234 5678901)'
    )

    class Meta(DjoserUserCreateSerializer.Meta):
        model = User
        fields = (
            'id',
            'username',
            'email',
            'password',
            'first_name',
            'last_name',
            'phone_number',
        )
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def validate_phone_number(self, value):
        """
        Validate phone_number format (optional).

        Args:
            value: The phone number string to validate

        Returns:
            The validated phone number

        Raises:
            ValidationError: If phone number format is invalid
        """
        if value and not value.startswith('+'):
            # Basic validation: phone numbers should start with + for international format
            # This is a simple validation; you can add more complex regex validation if needed
            pass  # Allow any format for now as it's optional
        return value


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom token serializer that accepts both username and email.

    This allows users to log in with either their username or email address.
    """

    username_field = User.USERNAME_FIELD

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make the username field accept both username and email
        self.fields[self.username_field] = serializers.CharField()
        self.fields['password'] = serializers.CharField(write_only=True)


class LogoutSerializer(serializers.Serializer):
    """
    Serializer for logout endpoint.

    Accepts refresh token to blacklist it during logout.
    """

    refresh = serializers.CharField(
        required=True,
        help_text='Refresh token to blacklist'
    )


class TwoFactorEnableSerializer(serializers.Serializer):
    """
    Serializer for enabling 2FA on user account.

    Initiates 2FA setup by sending verification code to user's email.
    """
    method = serializers.ChoiceField(
        choices=['email', 'phone'],
        required=False,
        help_text='2FA method to enable (email or phone). Defaults to user preference or system default.'
    )


class TwoFactorVerifySetupSerializer(serializers.Serializer):
    """
    Serializer for verifying 2FA setup code.

    Validates the 6-digit code sent to user's email during setup.
    """

    code = serializers.CharField(
        required=True,
        min_length=6,
        max_length=6,
        help_text='6-digit verification code sent to your email'
    )

    def validate_code(self, value):
        """
        Validate that code contains only digits.

        Args:
            value: The code string to validate

        Returns:
            The validated code

        Raises:
            ValidationError: If code is not numeric
        """
        if not value.isdigit():
            raise serializers.ValidationError('Code must contain only numbers.')
        return value


class TwoFactorDisableSerializer(serializers.Serializer):
    """
    Serializer for disabling 2FA on user account.

    Requires password confirmation for security (not required for OAuth users).
    """

    password = serializers.CharField(
        required=False,
        write_only=True,
        help_text='Current password for confirmation (required for non-OAuth users, optional for OAuth users)'
    )


class TwoFactorStatusSerializer(serializers.Serializer):
    """
    Serializer for 2FA status response.

    Returns whether user has 2FA enabled and setup date.
    """

    is_2fa_enabled = serializers.BooleanField()
    twofa_setup_date = serializers.DateTimeField(allow_null=True)
    preferred_2fa_method = serializers.CharField(allow_null=True, required=False)


class TwoFactorVerifyLoginSerializer(serializers.Serializer):
    """
    Serializer for verifying 2FA code during login.

    Accepts temporary token and verification code.
    """

    code = serializers.CharField(
        required=True,
        min_length=6,
        max_length=6,
        help_text='6-digit verification code sent to your email'
    )

    def validate_code(self, value):
        """
        Validate that code contains only digits.

        Args:
            value: The code string to validate

        Returns:
            The validated code

        Raises:
            ValidationError: If code is not numeric
        """
        if not value.isdigit():
            raise serializers.ValidationError('Code must contain only numbers.')
        return value


class TwoFactorResendSerializer(serializers.Serializer):
    """
    Serializer for resending 2FA verification code.

    No input fields needed, code is sent to authenticated user's email.
    """
    pass  # No input fields needed

