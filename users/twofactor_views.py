"""
Views for two-factor authentication endpoints.

Handles 2FA setup, verification, and management.
"""

from django.conf import settings
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, OpenApiResponse

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
    EmailVerificationSendSerializer,
    EmailVerificationVerifySerializer,
)
from users.twofactor_utils import generate_2fa_code, send_2fa_code_email, get_twofactor_settings
from users.oauth_adapters import generate_jwt_tokens


@extend_schema(
    tags=['Two-Factor Authentication'],
    summary='Enable 2FA for user account',
    description='Initiates 2FA setup by sending a verification code to user\'s email. Accepts optional method parameter (email or phone).',
    request=TwoFactorEnableSerializer,
    responses={
        200: OpenApiResponse(description='Verification code sent successfully'),
        400: OpenApiResponse(description='2FA is already enabled or email not verified'),
        501: OpenApiResponse(description='Phone 2FA not implemented yet'),
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
    summary='Verify 2FA setup code',
    description='Completes 2FA setup by verifying the code sent to user\'s email',
    request=TwoFactorVerifySetupSerializer,
    responses={
        200: OpenApiResponse(description='2FA enabled successfully'),
        400: OpenApiResponse(description='Invalid or expired code'),
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
            {'error': 'Invalid verification code.'},
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
    description='Disables 2FA after password confirmation',
    request=TwoFactorDisableSerializer,
    responses={
        200: OpenApiResponse(description='2FA disabled successfully'),
        400: OpenApiResponse(description='Invalid password or 2FA not enabled'),
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
    summary='Get 2FA status',
    description='Returns whether user has 2FA enabled and setup date',
    responses={
        200: TwoFactorStatusSerializer,
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
    description='Completes login by verifying 2FA code with temporary token and returning full JWT tokens',
    request=TwoFactorVerifyLoginSerializer,
    responses={
        200: OpenApiResponse(description='Full JWT tokens returned'),
        400: OpenApiResponse(description='Invalid or expired code'),
        401: OpenApiResponse(description='Invalid or expired temporary token'),
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
            {'error': 'Invalid verification code.'},
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
    summary='Resend 2FA verification code',
    description='Generates and sends a new 2FA code using temporary token',
    request=TwoFactorResendSerializer,
    responses={
        200: OpenApiResponse(description='New code sent successfully'),
        401: OpenApiResponse(description='Invalid or expired temporary token'),
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


@extend_schema(
    tags=['Email Verification'],
    summary='Send email verification code',
    description='Sends a verification code to user\'s email for email verification',
    request=EmailVerificationSendSerializer,
    responses={
        200: OpenApiResponse(description='Verification code sent successfully'),
        400: OpenApiResponse(description='Email already verified'),
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_email_verification_code(request):
    """
    Send email verification code to authenticated user.

    Generates and sends a 6-digit code for email verification.
    """
    user = request.user

    if user.email_verified:
        return Response(
            {'error': 'Email is already verified.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Get TwoFactorSettings
    settings_obj = get_twofactor_settings()
    if not settings_obj:
        settings_obj = TwoFactorSettings.get_solo()

    # Generate and send verification code
    twofactor_code = generate_2fa_code(user, settings_obj, verification_type='EMAIL_VERIFICATION')
    send_2fa_code_email(user, twofactor_code.code, verification_type='EMAIL_VERIFICATION')

    return Response(
        {
            'message': 'Verification code sent to your email.',
            'expires_at': twofactor_code.expires_at
        },
        status=status.HTTP_200_OK
    )


@extend_schema(
    tags=['Email Verification'],
    summary='Verify email with code',
    description='Verifies user email address with the code sent via email',
    request=EmailVerificationVerifySerializer,
    responses={
        200: OpenApiResponse(description='Email verified successfully'),
        400: OpenApiResponse(description='Invalid or expired code'),
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_email_code(request):
    """
    Verify email address with verification code.

    Validates the code and sets email_verified to True.
    """
    user = request.user
    serializer = EmailVerificationVerifySerializer(data=request.data)

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
            verification_type='EMAIL_VERIFICATION'
        ).latest('created_at')
    except TwoFactorCode.DoesNotExist:
        return Response(
            {'error': 'Invalid verification code.'},
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

    # Mark code as used and verify email
    twofactor_code.is_used = True
    twofactor_code.save()

    user.email_verified = True
    user.save()

    return Response(
        {'message': 'Email verified successfully.'},
        status=status.HTTP_200_OK
    )
