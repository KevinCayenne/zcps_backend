"""
Custom JWT token views with 2FA integration.

Overrides the default JWT token creation to support 2FA flow.
"""

from rest_framework import status, serializers
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema, OpenApiResponse, inline_serializer

from users.oauth_adapters import generate_temporary_2fa_token
from users.twofactor_utils import generate_2fa_code, send_2fa_code_email, get_twofactor_settings
from users.models import TwoFactorSettings


class CustomTokenObtainPairView(APIView):
    """
    Custom JWT token creation view with 2FA support.

    If user has 2FA enabled, generates a temporary token and sends
    verification code instead of returning full JWT tokens.

    If 2FA enforcement is enabled and user doesn't have 2FA, returns 403 error.
    """

    permission_classes = []  # Allow anyone to access login endpoint

    @extend_schema(
        tags=['Authentication'],
        summary='Obtain JWT token pair',
        description='Login with email/password. If 2FA is enabled, returns temporary token and sends verification code. If 2FA enforcement is enabled, users without 2FA will receive 403 error.',
        request=inline_serializer(
            name='LoginRequest',
            fields={
                'email': serializers.EmailField(required=False, help_text='User email address'),
                'username': serializers.CharField(required=False, help_text='Username'),
                'password': serializers.CharField(required=True, help_text='User password'),
            }
        ),
        responses={
            200: OpenApiResponse(description='JWT tokens or temporary token with 2FA prompt'),
            400: OpenApiResponse(description='Missing required fields'),
            401: OpenApiResponse(description='Invalid credentials'),
            403: OpenApiResponse(description='2FA required but not enabled'),
        }
    )
    def post(self, request, *args, **kwargs):
        """
        Handle login with 2FA check and enforcement.

        If user has 2FA enabled:
        - Generate and send 6-digit code via email
        - Return temporary token for 2FA verification

        If 2FA enforcement is enabled and user has 2FA disabled:
        - Return 403 error requiring user to enable 2FA

        If user has 2FA disabled and enforcement is disabled:
        - Return standard access and refresh tokens
        """
        from django.contrib.auth import authenticate
        from django.contrib.auth import get_user_model

        User = get_user_model()

        # Get credentials from request
        username_or_email = request.data.get('email') or request.data.get('username')
        password = request.data.get('password')

        if not username_or_email or not password:
            return Response(
                {'error': 'Email/username and password are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Try to authenticate with email or username
        user = authenticate(request, username=username_or_email, password=password)

        if not user:
            return Response(
                {'error': 'Invalid credentials.'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Get TwoFactorSettings to check enforcement policy
        settings_obj = get_twofactor_settings()
        if not settings_obj:
            settings_obj = TwoFactorSettings.get_solo()

        # Check if 2FA is enforced and user doesn't have it enabled
        if settings_obj.enforce_2fa_for_all_users and not user.is_2fa_enabled:
            return Response(
                {
                    'error': 'Two-factor authentication is required. Please enable 2FA at /auth/2fa/enable/',
                    'required_action': 'enable_2fa'
                },
                status=status.HTTP_403_FORBIDDEN
            )

        # Check if user has 2FA enabled
        if user.is_2fa_enabled:
            # Generate and send 2FA code
            twofactor_code = generate_2fa_code(user, settings_obj, verification_type='TWO_FACTOR')
            send_2fa_code_email(user, twofactor_code.code, verification_type='TWO_FACTOR')

            # Generate temporary token
            temp_token = generate_temporary_2fa_token(user)

            return Response(
                {
                    'temp_token': temp_token,
                    'requires_2fa': True,
                    'message': 'Verification code sent to your email. Please verify to complete login.',
                    'expires_at': twofactor_code.expires_at
                },
                status=status.HTTP_200_OK
            )

        # User doesn't have 2FA enabled and it's not enforced, generate and return standard tokens
        from users.oauth_adapters import generate_jwt_tokens
        access_token, refresh_token = generate_jwt_tokens(user)

        return Response(
            {
                'access': access_token,
                'refresh': refresh_token
            },
            status=status.HTTP_200_OK
        )
