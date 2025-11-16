"""
Views for two-factor authentication endpoints.

Handles 2FA setup, verification, and management.
"""

from django.conf import settings
from django.utils import timezone
from rest_framework import status, serializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiExample, inline_serializer

from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import TokenError

from users.models import TwoFactorCode, TwoFactorSettings
from users.serializers import (
    TwoFactorEnableSerializer,
    TwoFactorVerifySetupSerializer,
    TwoFactorDisableSerializer,
    TwoFactorStatusSerializer,
    TwoFactorVerifyLoginSerializer,
    TwoFactorResendSerializer,
)
from users.twofactor_utils import generate_2fa_code, send_2fa_code_email, get_twofactor_settings
from users.oauth_adapters import generate_jwt_tokens


@extend_schema(
    tags=['Two-Factor Authentication'],
    summary='Enable 2FA - Step 1: Request verification code',
    description="""
    Initiate two-factor authentication setup for your account.

    **Setup Workflow:**
    1. Call this endpoint to request verification code
    2. Check your email for 6-digit code
    3. Call `/auth/2fa/enable/verify/` with the code to complete setup

    **Methods:**
    - **email** (implemented): Sends code to user's email
    - **phone** (coming soon): Returns 501 Not Implemented

    **Important Notes:**
    - Requires authentication (Bearer token in Authorization header)
    - 2FA cannot be enabled if already active
    - Verification code expires in 10 minutes (configurable)
    - After 5 failed verification attempts, you must request a new code
    - Code is only valid for completing 2FA setup (not for login)
    """,
    request=TwoFactorEnableSerializer,
    examples=[
        OpenApiExample(
            'Enable 2FA with Email Method',
            value={'method': 'email'},
            request_only=True,
        ),
        OpenApiExample(
            'Enable 2FA (use system default)',
            value={},
            request_only=True,
        ),
        OpenApiExample(
            'Success Response',
            value={
                'message': 'Verification code sent to your email. Please verify to enable 2FA.',
                'method': 'email',
                'expires_at': '2025-11-15T12:10:00Z'
            },
            response_only=True,
            status_codes=['200'],
        ),
    ],
    responses={
        200: OpenApiResponse(
            description='Verification code sent successfully to user\'s email',
            response=inline_serializer(
                name='Enable2FASuccessResponse',
                fields={
                    'message': serializers.CharField(help_text='Success message'),
                    'method': serializers.CharField(help_text='2FA method: "email"'),
                    'expires_at': serializers.DateTimeField(help_text='When the verification code expires'),
                }
            )
        ),
        400: OpenApiResponse(
            description='Bad request - 2FA already enabled',
            response=inline_serializer(
                name='Enable2FABadRequestResponse',
                fields={
                    'error': serializers.CharField(help_text='Error message')
                }
            )
        ),
        401: OpenApiResponse(description='Unauthorized - Missing or invalid authentication token'),
        501: OpenApiResponse(
            description='Not Implemented - Phone 2FA requested but not yet available',
            response=inline_serializer(
                name='Enable2FANotImplementedResponse',
                fields={
                    'error': serializers.CharField(help_text='Error message: "Phone 2FA coming soon..."')
                }
            )
        ),
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def enable_2fa(request):
    """
    Enable 2FA for authenticated user.

    Generates and sends a verification code to user's email.
    User must verify the code to complete 2FA setup.
    """
    user = request.user
    serializer = TwoFactorEnableSerializer(data=request.data)

    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if user.is_2fa_enabled:
        return Response(
            {'error': '2FA is already enabled for your account.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Get method from request or use user's effective method
    method = serializer.validated_data.get('method')
    if not method:
        method = user.get_effective_2fa_method().lower()

    # Return 501 for phone method (not implemented in this revision)
    if method == 'phone':
        return Response(
            {'error': 'Phone 2FA coming soon. Please use email method for now.'},
            status=status.HTTP_501_NOT_IMPLEMENTED
        )

    # Store the selected method temporarily (will be saved after verification)
    request.session['pending_2fa_method'] = method.upper()

    # Get TwoFactorSettings
    settings_obj = get_twofactor_settings()
    if not settings_obj:
        settings_obj = TwoFactorSettings.get_solo()

    # Generate and send verification code
    twofactor_code = generate_2fa_code(user, settings_obj, verification_type='TWO_FACTOR')
    send_2fa_code_email(user, twofactor_code.code, verification_type='TWO_FACTOR')

    return Response(
        {
            'message': 'Verification code sent to your email. Please verify to enable 2FA.',
            'method': method,
            'expires_at': twofactor_code.expires_at
        },
        status=status.HTTP_200_OK
    )


@extend_schema(
    tags=['Two-Factor Authentication'],
    summary='Enable 2FA - Step 2: Verify code and complete setup',
    description="""
    Complete two-factor authentication setup by verifying the code sent to your email.

    **Prerequisites:**
    - Must have called `/auth/2fa/enable/` first
    - Must have received 6-digit code via email
    - Code must not be expired (10 minutes validity)
    - Must not exceed 5 failed verification attempts

    **On Success:**
    - User's `is_2fa_enabled` field is set to `True`
    - `twofa_setup_date` is recorded
    - `preferred_2fa_method` is saved
    - Future logins will require 2FA verification

    **Error Scenarios:**
    - Invalid code: Code doesn't match or doesn't exist
    - Expired code: Code older than 10 minutes
    - Code already used: Same code cannot be reused
    - Too many attempts: More than 5 failed attempts (request new code)
    """,
    request=TwoFactorVerifySetupSerializer,
    examples=[
        OpenApiExample(
            'Verify 2FA Setup',
            value={'code': '123456'},
            request_only=True,
        ),
        OpenApiExample(
            'Success Response',
            value={
                'message': '2FA has been enabled successfully.',
                'method': 'email'
            },
            response_only=True,
            status_codes=['200'],
        ),
    ],
    responses={
        200: OpenApiResponse(
            description='2FA enabled successfully',
            response=inline_serializer(
                name='Verify2FASetupSuccessResponse',
                fields={
                    'message': serializers.CharField(help_text='Success message'),
                    'method': serializers.CharField(help_text='2FA method that was enabled'),
                }
            )
        ),
        400: OpenApiResponse(
            description='Bad request - Invalid, expired, or already used code',
            response=inline_serializer(
                name='Verify2FASetupBadRequestResponse',
                fields={
                    'error': serializers.CharField(help_text='Error message explaining the issue')
                }
            )
        ),
        401: OpenApiResponse(description='Unauthorized - Missing or invalid authentication token'),
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_setup_2fa(request):
    """
    Verify 2FA setup code and enable 2FA for user.

    Validates the code and sets is_2fa_enabled to True.
    """
    user = request.user
    serializer = TwoFactorVerifySetupSerializer(data=request.data)

    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    code = serializer.validated_data['code']

    # Get TwoFactorSettings
    settings_obj = get_twofactor_settings()
    if not settings_obj:
        settings_obj = TwoFactorSettings.get_solo()

    max_attempts = settings_obj.max_failed_attempts

    # Find the most recent unused code for this user
    try:
        twofactor_code = TwoFactorCode.objects.filter(
            user=user,
            code=code,
            is_used=False,
            verification_type='TWO_FACTOR'
        ).latest('created_at')
    except TwoFactorCode.DoesNotExist:
        return Response(
            {'error': 'Invalid or expired verification code.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Check if code is valid
    if not twofactor_code.is_valid(max_attempts):
        if twofactor_code.expires_at <= timezone.now():
            return Response(
                {'error': 'Verification code has expired.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        elif twofactor_code.failed_attempts >= max_attempts:
            return Response(
                {'error': 'Too many failed attempts. Please request a new code.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        else:
            return Response(
                {'error': 'Verification code has already been used.'},
                status=status.HTTP_400_BAD_REQUEST
            )

    # Mark code as used and enable 2FA
    twofactor_code.is_used = True
    twofactor_code.save()

    # Get pending method from session
    pending_method = request.session.get('pending_2fa_method', 'EMAIL')

    user.is_2fa_enabled = True
    user.twofa_setup_date = timezone.now()
    user.preferred_2fa_method = pending_method
    user.save()

    # Clear session
    if 'pending_2fa_method' in request.session:
        del request.session['pending_2fa_method']

    return Response(
        {
            'message': '2FA has been enabled successfully.',
            'method': pending_method.lower()
        },
        status=status.HTTP_200_OK
    )


@extend_schema(
    tags=['Two-Factor Authentication'],
    summary='Disable 2FA for user account',
    description="""
    Disable two-factor authentication for your account.

    **Security Requirements:**
    - Requires current password confirmation
    - Only works if 2FA is currently enabled

    **What Happens:**
    - User's `is_2fa_enabled` field is set to `False`
    - All unused 2FA codes are invalidated
    - Future logins will NOT require 2FA verification
    - User can re-enable 2FA at any time

    **Important Notes:**
    - If system-wide 2FA enforcement is enabled, you will not be able to log in after disabling 2FA
    - Check with administrator before disabling if enforcement is active
    """,
    request=TwoFactorDisableSerializer,
    examples=[
        OpenApiExample(
            'Disable 2FA',
            value={'password': 'SecurePass123!'},
            request_only=True,
        ),
        OpenApiExample(
            'Success Response',
            value={'message': '2FA has been disabled successfully.'},
            response_only=True,
            status_codes=['200'],
        ),
    ],
    responses={
        200: OpenApiResponse(
            description='2FA disabled successfully',
            response=inline_serializer(
                name='Disable2FASuccessResponse',
                fields={
                    'message': serializers.CharField(help_text='Success message')
                }
            )
        ),
        400: OpenApiResponse(
            description='Bad request - Invalid password or 2FA not enabled',
            response=inline_serializer(
                name='Disable2FABadRequestResponse',
                fields={
                    'error': serializers.CharField(help_text='Error message')
                }
            )
        ),
        401: OpenApiResponse(description='Unauthorized - Missing or invalid authentication token'),
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def disable_2fa(request):
    """
    Disable 2FA for authenticated user.

    Requires password confirmation for security.
    """
    user = request.user
    serializer = TwoFactorDisableSerializer(data=request.data)

    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if not user.is_2fa_enabled:
        return Response(
            {'error': '2FA is not enabled for your account.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Verify password
    password = serializer.validated_data['password']
    if not user.check_password(password):
        return Response(
            {'error': 'Invalid password.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Disable 2FA
    user.is_2fa_enabled = False
    user.save()

    # Invalidate any unused codes
    TwoFactorCode.objects.filter(
        user=user,
        is_used=False
    ).update(is_used=True)

    return Response(
        {'message': '2FA has been disabled successfully.'},
        status=status.HTTP_200_OK
    )


@extend_schema(
    tags=['Two-Factor Authentication'],
    summary='Get 2FA status for current user',
    description="""
    Check whether two-factor authentication is enabled for your account.

    **Response Fields:**
    - `is_2fa_enabled`: Boolean indicating if 2FA is active
    - `twofa_setup_date`: Timestamp when 2FA was first enabled (null if not enabled)
    - `preferred_2fa_method`: User's preferred 2FA method ("EMAIL" or "PHONE")

    **Use Cases:**
    - Check if user needs to complete 2FA setup
    - Display 2FA status in user profile/settings
    - Determine if user can disable 2FA
    """,
    examples=[
        OpenApiExample(
            'Success Response (2FA Enabled)',
            value={
                'is_2fa_enabled': True,
                'twofa_setup_date': '2025-11-15T10:30:00Z',
                'preferred_2fa_method': 'EMAIL'
            },
            response_only=True,
            status_codes=['200'],
        ),
        OpenApiExample(
            'Success Response (2FA Not Enabled)',
            value={
                'is_2fa_enabled': False,
                'twofa_setup_date': None,
                'preferred_2fa_method': None
            },
            response_only=True,
            status_codes=['200'],
        ),
    ],
    responses={
        200: TwoFactorStatusSerializer,
        401: OpenApiResponse(description='Unauthorized - Missing or invalid authentication token'),
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_2fa_status(request):
    """
    Get 2FA status for authenticated user.

    Returns whether user has 2FA enabled and when it was set up.
    """
    user = request.user
    serializer = TwoFactorStatusSerializer({
        'is_2fa_enabled': user.is_2fa_enabled,
        'twofa_setup_date': user.twofa_setup_date,
        'preferred_2fa_method': user.preferred_2fa_method
    })

    return Response(serializer.data, status=status.HTTP_200_OK)


@extend_schema(
    tags=['Two-Factor Authentication'],
    summary='Verify 2FA code during login',
    description="""
    Complete the login process by verifying the 2FA code sent to your email.

    **Prerequisites:**
    - Must have received `temp_token` from `/auth/jwt/create/` login endpoint
    - Must have 6-digit code from email
    - Temporary token must not be expired (10 minutes validity)
    - Code must not be expired (10 minutes validity)

    **Authentication:**
    - Use the `temp_token` in the Authorization header: `Bearer {temp_token}`
    - Regular access tokens will NOT work for this endpoint

    **Workflow:**
    1. Login returns `temp_token` and sends code to email
    2. User receives 6-digit code via email
    3. Call this endpoint with temp_token and code
    4. Receive full JWT tokens (access + refresh)
    5. Use access token for subsequent API calls

    **On Success:**
    - Full JWT access and refresh tokens are returned
    - Temporary token becomes invalid
    - 2FA code is marked as used
    - User's `last_2fa_verification` timestamp is updated
    """,
    request=TwoFactorVerifyLoginSerializer,
    examples=[
        OpenApiExample(
            'Verify 2FA Login',
            value={'code': '654321'},
            request_only=True,
        ),
        OpenApiExample(
            'Success Response',
            value={
                'access': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...',
                'refresh': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...',
                'message': '2FA verification successful.'
            },
            response_only=True,
            status_codes=['200'],
        ),
    ],
    responses={
        200: OpenApiResponse(
            description='2FA verification successful, full JWT tokens returned',
            response=inline_serializer(
                name='Verify2FALoginSuccessResponse',
                fields={
                    'access': serializers.CharField(help_text='JWT access token (expires in 15 min)'),
                    'refresh': serializers.CharField(help_text='JWT refresh token (expires in 7 days)'),
                    'message': serializers.CharField(help_text='Success message'),
                }
            )
        ),
        400: OpenApiResponse(
            description='Bad request - Invalid or expired verification code',
            response=inline_serializer(
                name='Verify2FALoginBadRequestResponse',
                fields={
                    'error': serializers.CharField(help_text='Error message explaining the issue')
                }
            )
        ),
        401: OpenApiResponse(
            description='Unauthorized - Invalid or expired temporary token',
            response=inline_serializer(
                name='Verify2FALoginUnauthorizedResponse',
                fields={
                    'error': serializers.CharField(help_text='Error message about token issue')
                }
            )
        ),
    }
)
@api_view(['POST'])
def verify_2fa_login(request):
    """
    Verify 2FA code during login and return full JWT tokens.

    Validates temporary token and verification code, then returns
    standard access and refresh JWT tokens.
    """
    # Get temporary token from Authorization header
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if not auth_header.startswith('Bearer '):
        return Response(
            {'error': 'Temporary token required in Authorization header.'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    temp_token_str = auth_header.split(' ')[1]

    # Validate temporary token
    try:
        temp_token = AccessToken(temp_token_str)
    except TokenError:
        return Response(
            {'error': 'Invalid or expired temporary token.'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    # Check if token has temp_2fa claim
    if not temp_token.get('temp_2fa'):
        return Response(
            {'error': 'Invalid token type. Temporary 2FA token required.'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    # Get user from token
    user_id = temp_token.get('user_id')
    if not user_id:
        return Response(
            {'error': 'Invalid token.'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    from django.contrib.auth import get_user_model
    User = get_user_model()

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response(
            {'error': 'User not found.'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    # Validate code input
    serializer = TwoFactorVerifyLoginSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    code = serializer.validated_data['code']

    # Get TwoFactorSettings
    settings_obj = get_twofactor_settings()
    if not settings_obj:
        settings_obj = TwoFactorSettings.get_solo()

    max_attempts = settings_obj.max_failed_attempts

    # Find the most recent unused code for this user
    try:
        twofactor_code = TwoFactorCode.objects.filter(
            user=user,
            code=code,
            is_used=False,
            verification_type='TWO_FACTOR'
        ).latest('created_at')
    except TwoFactorCode.DoesNotExist:
        return Response(
            {'error': 'Invalid or expired verification code.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Check if code is valid
    if not twofactor_code.is_valid(max_attempts):
        if twofactor_code.expires_at <= timezone.now():
            return Response(
                {'error': 'Verification code has expired. Please request a new code.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        elif twofactor_code.failed_attempts >= max_attempts:
            return Response(
                {'error': 'Too many failed attempts. Please request a new code.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        else:
            return Response(
                {'error': 'Verification code has already been used.'},
                status=status.HTTP_400_BAD_REQUEST
            )

    # Mark code as used and update user's last verification timestamp
    twofactor_code.is_used = True
    twofactor_code.save()

    user.last_2fa_verification = timezone.now()
    user.save()

    # Generate full JWT tokens
    access_token, refresh_token = generate_jwt_tokens(user)

    return Response(
        {
            'access': access_token,
            'refresh': refresh_token,
            'message': '2FA verification successful.'
        },
        status=status.HTTP_200_OK
    )


@extend_schema(
    tags=['Two-Factor Authentication'],
    summary='Resend 2FA verification code during login',
    description="""
    Request a new 2FA verification code during the login process.

    **Use Cases:**
    - Previous code expired (after 10 minutes)
    - Code was not received or lost
    - Too many failed verification attempts with previous code

    **Prerequisites:**
    - Must have `temp_token` from login endpoint
    - Use temp_token in Authorization header: `Bearer {temp_token}`

    **What Happens:**
    - All previous unused 2FA codes are invalidated
    - New 6-digit code is generated
    - New code is sent to user's email
    - New expiration time is set (10 minutes from now)
    - Temporary token remains valid

    **Important Notes:**
    - No request body needed
    - Only works with temporary 2FA tokens
    - Regular access tokens will not work
    """,
    request=TwoFactorResendSerializer,
    examples=[
        OpenApiExample(
            'Success Response',
            value={
                'message': 'New verification code sent to your email.',
                'expires_at': '2025-11-15T12:20:00Z'
            },
            response_only=True,
            status_codes=['200'],
        ),
    ],
    responses={
        200: OpenApiResponse(
            description='New verification code sent successfully',
            response=inline_serializer(
                name='Resend2FASuccessResponse',
                fields={
                    'message': serializers.CharField(help_text='Success message'),
                    'expires_at': serializers.DateTimeField(help_text='When the new code expires'),
                }
            )
        ),
        401: OpenApiResponse(
            description='Unauthorized - Invalid or expired temporary token',
            response=inline_serializer(
                name='Resend2FAUnauthorizedResponse',
                fields={
                    'error': serializers.CharField(help_text='Error message about token issue')
                }
            )
        ),
    }
)
@api_view(['POST'])
def resend_2fa_code(request):
    """
    Resend 2FA verification code during login.

    Generates a new code and invalidates the previous one.
    """
    # Get temporary token from Authorization header
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if not auth_header.startswith('Bearer '):
        return Response(
            {'error': 'Temporary token required in Authorization header.'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    temp_token_str = auth_header.split(' ')[1]

    # Validate temporary token
    try:
        temp_token = AccessToken(temp_token_str)
    except TokenError:
        return Response(
            {'error': 'Invalid or expired temporary token.'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    # Check if token has temp_2fa claim
    if not temp_token.get('temp_2fa'):
        return Response(
            {'error': 'Invalid token type. Temporary 2FA token required.'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    # Get user from token
    user_id = temp_token.get('user_id')
    if not user_id:
        return Response(
            {'error': 'Invalid token.'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    from django.contrib.auth import get_user_model
    User = get_user_model()

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response(
            {'error': 'User not found.'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    # Get TwoFactorSettings
    settings_obj = get_twofactor_settings()
    if not settings_obj:
        settings_obj = TwoFactorSettings.get_solo()

    # Generate and send new verification code
    twofactor_code = generate_2fa_code(user, settings_obj, verification_type='TWO_FACTOR')
    send_2fa_code_email(user, twofactor_code.code, verification_type='TWO_FACTOR')

    return Response(
        {
            'message': 'New verification code sent to your email.',
            'expires_at': twofactor_code.expires_at
        },
        status=status.HTTP_200_OK
    )

