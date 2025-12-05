"""
Serializers for User model and authentication.

Provides custom serializers for user registration and profile management.
"""

from rest_framework import serializers
from django.contrib.auth import get_user_model
from djoser.serializers import UserCreateSerializer as DjoserUserCreateSerializer
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

User = get_user_model()

# 避免循環導入，在需要時才導入
# 注意：不能導入 clinic.serializers，因為它會導入 UserSerializer，造成循環導入
try:
    from clinic.models import ClinicUserPermission, Clinic
except ImportError:
    ClinicUserPermission = None
    Clinic = None


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for User model (read and write operations).

    Used for displaying and creating user profile information.
    Automatically generates unique username if not provided during creation.
    """

    username = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text='Username (optional, will be auto-generated from email if not provided)'
    )
    
    # 診所權限相關欄位
    clinic_permissions = serializers.SerializerMethodField(
        read_only=True,
        help_text='該用戶的診所權限列表（只讀）'
    )
    clinic_ids = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        required=False,
        allow_empty=True,
        help_text='診所 ID 列表（寫入時用於設置該用戶的診所權限）'
    )

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
            'clinic_permissions',
            'clinic_ids',
        )
        read_only_fields = (
            'id',
            'username',
            'password',
            'created_at',
            'updated_at',
            'email_verified',
            'phone_number_verified',
            'twofa_setup_date',
            'last_2fa_verification',
            'last_login',
            'date_joined',
            'clinic_permissions',
        )
    
    def get_clinic_permissions(self, obj):
        """獲取該用戶的所有診所權限"""
        if ClinicUserPermission is None:
            return []
        
        permissions = ClinicUserPermission.objects.filter(user=obj).select_related('clinic')
        
        # 直接返回簡化版本，避免使用 ClinicUserPermissionSerializer
        # 因為 ClinicUserPermissionSerializer 使用 UserSerializer，會造成循環引用
        return [
            {
                'id': perm.id,
                'clinic_id': perm.clinic.id,
                'clinic_name': perm.clinic.name,
                'clinic_number': perm.clinic.number if hasattr(perm.clinic, 'number') else None,
                'create_time': perm.create_time,
                'update_time': perm.update_time,
            }
            for perm in permissions
        ]
    
    def validate_clinic_ids(self, value):
        """驗證診所 ID 列表"""
        if Clinic is None:
            raise serializers.ValidationError("診所模組未可用")
        
        if not isinstance(value, list):
            raise serializers.ValidationError("clinic_ids 必須是一個列表")
        
        # 驗證所有診所是否存在
        clinic_ids = list(set(value))  # 去重
        existing_clinics = Clinic.objects.filter(id__in=clinic_ids)
        existing_ids = set(existing_clinics.values_list('id', flat=True))
        missing_ids = set(clinic_ids) - existing_ids
        
        if missing_ids:
            raise serializers.ValidationError(
                f"以下診所 ID 不存在: {', '.join(map(str, missing_ids))}"
            )
        
        return clinic_ids

    def create(self, validated_data):
        """
        Create a new user instance.
        
        Automatically generates a unique username if not provided or empty.
        Username is generated from email address.
        """
        import uuid
        
        # Get username from validated_data
        username = validated_data.get('username', '').strip() if validated_data.get('username') else ''
        
        # If username is provided and already exists, raise validation error
        if username and User.objects.filter(username=username).exists():
            raise serializers.ValidationError({
                'username': ['此使用者帳號已被使用。']
            })

        # If username is not provided or is empty, generate one from email
        if not username:
            email = validated_data.get('email', '')
            if email:
                # Generate username from email (part before @)
                base_username = email.split('@')[0]
                # Remove any non-alphanumeric characters except underscore
                base_username = ''.join(c for c in base_username if c.isalnum() or c == '_')
                # Ensure it's not empty
                if not base_username:
                    base_username = 'user'
                
                # Make it unique by appending a counter if needed
                username = base_username
                counter = 1
                while User.objects.filter(username=username).exists():
                    username = f"{base_username}_{counter}"
                    counter += 1
                    # Safety limit to prevent infinite loop
                    if counter > 1000:
                        username = f"{base_username}_{uuid.uuid4().hex[:8]}"
                        break
            else:
                # Fallback if no email (shouldn't happen, but just in case)
                username = f"user_{uuid.uuid4().hex[:8]}"
        
        # Set the username (generated or provided)
        validated_data['username'] = username
        
        # Create the user
        return super().create(validated_data)


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
            'last_2fa_verification',
            'role',
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

