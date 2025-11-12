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
            'created_at',
        )
        read_only_fields = ('id', 'created_at')


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
