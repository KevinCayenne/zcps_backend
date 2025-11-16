"""
Custom JWT token views with 2FA integration.

Overrides the default JWT token creation to support 2FA flow.
"""

from rest_framework import status, serializers
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiExample, inline_serializer
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

from users.oauth_adapters import generate_temporary_2fa_token
from users.twofactor_utils import generate_2fa_code, send_2fa_code, get_twofactor_settings
from users.models import TwoFactorSettings


class CustomTokenObtainPairView(APIView):
    """
    Custom JWT token creation view with 2FA support.

    If user has 2FA enabled, generates a temporary token and sends
    verification code instead of returning full JWT tokens.

    If 2FA enforcement is enabled and user doesn't have 2FA, returns 403 error.
    """

    permission_classes = [AllowAny]  # Allow anyone to access login endpoint

    @extend_schema(
        tags=['Authentication'],
        summary='Login and obtain JWT tokens (Public)',
        description="""
        Authenticate user and obtain JWT access and refresh tokens.

        **Authentication Flow:**

        1. **Without 2FA:** Returns standard JWT tokens immediately
        2. **With 2FA Enabled:** Returns temporary token and sends 6-digit code to email
        3. **With 2FA Enforcement (user has 2FA):** Returns setup_token to enable 2FA first

        **Important Notes:**
        - You can login with either email OR username
        - Temporary tokens expire in 10 minutes (configurable)
        - Temporary tokens only work with 2FA-related endpoints
        - After 2FA verification, use the returned access/refresh tokens for API calls

        **Example Workflow (With 2FA Already Enabled):**
        1. Login → Receive temp_token
        2. Check email for 6-digit code
        3. Call `/auth/2fa/verify/` with temp_token and code
        4. Receive full JWT tokens

        **Example Workflow (2FA Enforcement but User Hasn't Enabled 2FA):**
        1. Login → Receive setup_token
        2. Call `/auth/2fa/enable/` with setup_token to start 2FA setup
        3. Check email for 6-digit setup code
        4. Call `/auth/2fa/enable/verify/` with setup_token and code
        5. Login again → Now follows normal 2FA flow
        """,
        request=inline_serializer(
            name='LoginRequest',
            fields={
                'email': serializers.EmailField(
                    required=False,
                    help_text='User email address (use email OR username, not both)'
                ),
                'username': serializers.CharField(
                    required=False,
                    help_text='Username (use email OR username, not both)'
                ),
                'password': serializers.CharField(
                    required=True,
                    help_text='User password',
                    write_only=True
                ),
            }
        ),
        examples=[
            OpenApiExample(
                'Login with Email (No 2FA)',
                value={
                    'email': 'user@example.com',
                    'password': 'SecurePass123!'
                },
                request_only=True,
            ),
            OpenApiExample(
                'Login with Username (No 2FA)',
                value={
                    'username': 'johndoe',
                    'password': 'SecurePass123!'
                },
                request_only=True,
            ),
            OpenApiExample(
                'Success Response (No 2FA)',
                value={
                    'access': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...',
                    'refresh': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...'
                },
                response_only=True,
                status_codes=['200'],
            ),
            OpenApiExample(
                'Success Response (2FA Required - User Has 2FA)',
                value={
                    'temp_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...',
                    'requires_2fa': True,
                    'message': 'Verification code sent to your email. Please verify to complete login.',
                    'expires_at': '2025-11-15T12:10:00Z'
                },
                response_only=True,
                status_codes=['200'],
            ),
            OpenApiExample(
                'Success Response (2FA Enforcement - User Needs Setup)',
                value={
                    'setup_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...',
                    'requires_2fa_setup': True,
                    'message': 'Two-factor authentication is required. Use this token to set up 2FA at /auth/2fa/enable/',
                    'allowed_endpoints': ['/auth/2fa/enable/', '/auth/2fa/enable/verify/', '/auth/2fa/status/']
                },
                response_only=True,
                status_codes=['200'],
            ),
        ],
        responses={
            200: OpenApiResponse(
                description='Login successful. Returns JWT tokens, temporary token, or setup token based on 2FA status.',
                response=inline_serializer(
                    name='LoginSuccessResponse',
                    fields={
                        'access': serializers.CharField(help_text='JWT access token (expires in 15 min)'),
                        'refresh': serializers.CharField(help_text='JWT refresh token (expires in 7 days)'),
                        'temp_token': serializers.CharField(help_text='Temporary 2FA token (only if user has 2FA enabled)'),
                        'setup_token': serializers.CharField(help_text='Setup token (only if 2FA enforcement requires setup)'),
                        'requires_2fa': serializers.BooleanField(help_text='Whether 2FA verification is required'),
                        'requires_2fa_setup': serializers.BooleanField(help_text='Whether user needs to setup 2FA first'),
                        'message': serializers.CharField(help_text='Status message'),
                        'expires_at': serializers.DateTimeField(help_text='When the 2FA code expires'),
                        'allowed_endpoints': serializers.ListField(help_text='Endpoints allowed with setup token'),
                    }
                )
            ),
            400: OpenApiResponse(
                description='Bad request - Missing email/username or password',
                response=inline_serializer(
                    name='LoginBadRequestResponse',
                    fields={
                        'error': serializers.CharField(help_text='Error message')
                    }
                )
            ),
            401: OpenApiResponse(
                description='Unauthorized - Invalid credentials',
                response=inline_serializer(
                    name='LoginUnauthorizedResponse',
                    fields={
                        'error': serializers.CharField(help_text='Error message: "Invalid credentials."')
                    }
                )
            ),
            403: OpenApiResponse(
                description='Forbidden - 2FA enforcement enabled but user has not enabled 2FA',
                response=inline_serializer(
                    name='LoginForbiddenResponse',
                    fields={
                        'error': serializers.CharField(help_text='Error message explaining 2FA is required'),
                        'required_action': serializers.CharField(help_text='Action required: "enable_2fa"')
                    }
                )
            ),
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
            # Generate a setup token that ONLY allows access to 2FA setup endpoints
            # This token has 'setup_2fa' claim which is checked by middleware
            temp_token = generate_temporary_2fa_token(user)

            return Response(
                {
                    'setup_token': temp_token,
                    'requires_2fa_setup': True,
                    'message': 'Two-factor authentication is required. Use this token to set up 2FA at /auth/2fa/enable/',
                    'allowed_endpoints': ['/auth/2fa/enable/', '/auth/2fa/enable/verify/', '/auth/2fa/status/']
                },
                status=status.HTTP_200_OK
            )

        # Check if user has 2FA enabled
        if user.is_2fa_enabled:
            # Generate and send 2FA code
            twofactor_code = generate_2fa_code(user, settings_obj, verification_type='TWO_FACTOR')
            send_2fa_code(user, twofactor_code.code, verification_type='TWO_FACTOR')

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


class CustomTokenRefreshView(TokenRefreshView):
    """
    Custom JWT token refresh view with enhanced documentation.

    Wraps SimpleJWT's TokenRefreshView to add detailed Swagger documentation.
    """

    permission_classes = [AllowAny]  # Allow anyone to access login endpoint

    @extend_schema(
        tags=['Authentication'],
        summary='Refresh JWT access token (Public)',
        description="""
        Obtain a new access token using your refresh token.

        **Use Case:**
        - Access tokens expire after 15 minutes (default)
        - Use this endpoint to get a new access token without logging in again
        - Refresh token remains valid for 7 days (default)

        **Workflow:**
        1. Detect that access token is expired (401 error)
        2. Call this endpoint with refresh token
        3. Receive new access token
        4. Continue making API calls with new access token

        **Important Notes:**
        - Refresh token must not be blacklisted
        - Refresh token must not be expired
        - After logout, refresh tokens are blacklisted
        - Each refresh returns only a new access token (refresh token stays the same)

        **Security:**
        - Store refresh tokens securely (httpOnly cookies recommended for web apps)
        - Never expose refresh tokens in URLs or logs
        - Refresh tokens can be blacklisted via logout endpoint
        """,
        request=inline_serializer(
            name='TokenRefreshRequest',
            fields={
                'refresh': serializers.CharField(
                    required=True,
                    help_text='Your refresh token from login'
                )
            }
        ),
        examples=[
            OpenApiExample(
                'Refresh Token Request',
                value={'refresh': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...'},
                request_only=True,
            ),
            OpenApiExample(
                'Success Response',
                value={'access': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...'},
                response_only=True,
                status_codes=['200'],
            ),
        ],
        responses={
            200: OpenApiResponse(
                description='New access token generated successfully',
                response=inline_serializer(
                    name='TokenRefreshSuccessResponse',
                    fields={
                        'access': serializers.CharField(help_text='New JWT access token (expires in 15 min)')
                    }
                )
            ),
            401: OpenApiResponse(
                description='Unauthorized - Invalid, expired, or blacklisted refresh token',
                response=inline_serializer(
                    name='TokenRefreshUnauthorizedResponse',
                    fields={
                        'detail': serializers.CharField(help_text='Error message'),
                        'code': serializers.CharField(help_text='Error code: "token_not_valid"')
                    }
                )
            ),
        }
    )
    def post(self, request, *args, **kwargs):
        """Handle token refresh with enhanced documentation."""
        return super().post(request, *args, **kwargs)


class CustomTokenVerifyView(TokenVerifyView):
    """
    Custom JWT token verify view with enhanced documentation.

    Wraps SimpleJWT's TokenVerifyView to add detailed Swagger documentation.
    """

    permission_classes = [AllowAny]  # Allow anyone to access login endpoint

    @extend_schema(
        tags=['Authentication'],
        summary='Verify JWT token validity (Public)',
        description="""
        Check if a JWT token (access or refresh) is valid.

        **Use Cases:**
        - Verify token before making important operations
        - Check if token is expired before attempting refresh
        - Validate tokens received from external sources

        **Response:**
        - `200 OK`: Token is valid and not expired
        - `401 Unauthorized`: Token is invalid, expired, or blacklisted

        **What This Checks:**
        - Token signature is valid
        - Token has not expired
        - Token has not been blacklisted (for refresh tokens)
        - Token structure is correct

        **Important Notes:**
        - This endpoint does NOT return a new token
        - Works with both access and refresh tokens
        - Temporary 2FA tokens will also be validated
        - No body content in successful response (just 200 status)
        """,
        request=inline_serializer(
            name='TokenVerifyRequest',
            fields={
                'token': serializers.CharField(
                    required=True,
                    help_text='JWT token to verify (access, refresh, or temporary)'
                )
            }
        ),
        examples=[
            OpenApiExample(
                'Verify Token Request',
                value={'token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...'},
                request_only=True,
            ),
        ],
        responses={
            200: OpenApiResponse(description='Token is valid (no content returned)'),
            401: OpenApiResponse(
                description='Unauthorized - Token is invalid, expired, or blacklisted',
                response=inline_serializer(
                    name='TokenVerifyUnauthorizedResponse',
                    fields={
                        'detail': serializers.CharField(help_text='Error message'),
                        'code': serializers.CharField(help_text='Error code: "token_not_valid"')
                    }
                )
            ),
        }
    )
    def post(self, request, *args, **kwargs):
        """Handle token verification with enhanced documentation."""
        return super().post(request, *args, **kwargs)
