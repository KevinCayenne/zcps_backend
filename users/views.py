"""
Views for user authentication and profile management.

Provides custom views for logout functionality with token blacklisting,
and custom password management views with JWT token blacklisting.
"""

from rest_framework import status, serializers
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiExample, inline_serializer
from djoser.views import UserViewSet
from django.conf import settings
from .serializers import LogoutSerializer
from .utils import blacklist_user_tokens


class LogoutView(APIView):
    """
    Custom logout view that blacklists the refresh token.

    POST /auth/logout/
    Requires authentication and accepts refresh token in request body.
    Blacklists the token to prevent further use.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = LogoutSerializer

    @extend_schema(
        tags=['Authentication'],
        summary='Logout and blacklist refresh token',
        description="""
        Logout the current user by blacklisting their refresh token.

        **What Happens:**
        - Refresh token is added to the blacklist
        - Token can no longer be used to obtain new access tokens
        - User must login again to get new tokens

        **Prerequisites:**
        - Must be authenticated (Bearer access token in Authorization header)
        - Must provide refresh token in request body

        **Important Notes:**
        - Access token remains valid until its natural expiration (15 minutes)
        - To fully invalidate access immediately, implement token versioning
        - Blacklist is permanent for that specific refresh token
        - After logout, call `/auth/jwt/create/` to login again

        **Security:**
        - Always logout when users click "Sign Out"
        - Helps prevent unauthorized access if refresh token is compromised
        - Token blacklist is stored in database
        """,
        request=LogoutSerializer,
        examples=[
            OpenApiExample(
                'Logout Request',
                value={'refresh': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...'},
                request_only=True,
            ),
        ],
        responses={
            204: OpenApiResponse(description='Logout successful, token blacklisted (no content returned)'),
            400: OpenApiResponse(
                description='Bad Request - Invalid or missing refresh token',
                response=inline_serializer(
                    name='LogoutBadRequestResponse',
                    fields={
                        'detail': serializers.CharField(help_text='Error message')
                    }
                )
            ),
            401: OpenApiResponse(description='Unauthorized - Missing or invalid access token in Authorization header'),
        }
    )
    def post(self, request):
        """
        Blacklist the refresh token to log out the user.

        Args:
            request: The HTTP request object containing refresh token

        Returns:
            Response with 204 No Content on success
            Response with 400 Bad Request if token is invalid or missing
        """
        refresh_token = request.data.get('refresh')

        if not refresh_token:
            return Response(
                {'detail': 'Refresh token is required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except TokenError as e:
            return Response(
                {'detail': 'Invalid token or token already blacklisted.'},
                status=status.HTTP_400_BAD_REQUEST
            )


class CustomUserViewSet(UserViewSet):
    """
    Custom UserViewSet that extends Djoser's UserViewSet.

    Adds JWT token blacklisting functionality to password reset and
    password change operations for enhanced security.
    """

    @extend_schema(
        tags=['User Management'],
        summary='Register new user account',
        description="""
        Create a new user account with email and password.

        **Registration Flow:**
        1. Submit email, username, and password
        2. Account is created (inactive if activation required)
        3. Activation email is sent (if SEND_ACTIVATION_EMAIL=True)
        4. User must click activation link to activate account
        5. After activation, user can login at `/auth/jwt/create/`

        **Email Activation:**
        - If enabled: Check email for activation link
        - Activation link format: `{FRONTEND_URL}/activate/{uid}/{token}`
        - Click link or call `/auth/users/activation/` with uid/token
        - Account becomes active after successful activation

        **Important Notes:**
        - Email must be unique
        - Username is optional (can login with email)
        - Password must meet validation requirements
        - Email verification is separate from account activation
        - OAuth users are auto-activated

        **After Registration:**
        - Wait for activation email (if enabled)
        - Activate account via link or API
        - Login at `/auth/jwt/create/` to get tokens
        """,
        examples=[
            OpenApiExample(
                'Registration Request',
                value={
                    'email': 'newuser@example.com',
                    'username': 'newuser',
                    'password': 'SecurePass123!'
                },
                request_only=True,
            ),
            OpenApiExample(
                'Success Response',
                value={
                    'id': 1,
                    'email': 'newuser@example.com',
                    'username': 'newuser'
                },
                response_only=True,
                status_codes=['201'],
            ),
        ],
        responses={
            201: OpenApiResponse(description='User created successfully. Check email for activation if required.'),
            400: OpenApiResponse(
                description='Bad Request - Validation errors',
                response=inline_serializer(
                    name='UserRegistrationErrorResponse',
                    fields={
                        'email': serializers.ListField(help_text='Email validation errors'),
                        'username': serializers.ListField(help_text='Username validation errors'),
                        'password': serializers.ListField(help_text='Password validation errors'),
                    }
                )
            ),
        }
    )
    def create(self, request, *args, **kwargs):
        """Create a new user account."""
        return super().create(request, *args, **kwargs)

    @extend_schema(
        tags=['User Management'],
        summary='List all users (Admin only)',
        description="""
        Retrieve a list of all user accounts in the system.

        **What You Get:**
        - Array of user objects
        - Basic profile information for each user
        - Paginated results (if pagination is enabled)

        **Prerequisites:**
        - **Admin privileges required** (is_staff=True)
        - Must be authenticated with admin account

        **Common Use Cases:**
        - Admin user management interface
        - User directory/search
        - Analytics and reporting

        **Security:**
        - This endpoint is ADMIN-ONLY
        - Regular users will receive 403 Forbidden
        - Use `/auth/users/me/` for current user profile instead
        """,
        examples=[
            OpenApiExample(
                'Success Response',
                value=[
                    {
                        'id': 1,
                        'email': 'user1@example.com',
                        'username': 'user1'
                    },
                    {
                        'id': 2,
                        'email': 'user2@example.com',
                        'username': 'user2'
                    }
                ],
                response_only=True,
                status_codes=['200'],
            ),
        ],
        responses={
            200: OpenApiResponse(description='List of users retrieved successfully'),
            401: OpenApiResponse(description='Unauthorized - Missing or invalid access token'),
            403: OpenApiResponse(description='Forbidden - Insufficient permissions to list users'),
        }
    )
    def list(self, request, *args, **kwargs):
        """List all users."""
        return super().list(request, *args, **kwargs)

    @extend_schema(
        tags=['User Management'],
        summary='Get user by ID (Admin only)',
        description="""
        Retrieve a specific user's profile information by their user ID.

        **What You Get:**
        - User ID
        - Email address
        - Username
        - Email verification status
        - 2FA status
        - Other profile fields

        **Prerequisites:**
        - **Admin privileges required** (is_staff=True)
        - Must be authenticated with admin account

        **Common Use Cases:**
        - Admin user management
        - User lookup by ID for admin purposes
        - Customer support

        **Important Notes:**
        - Different from `/auth/users/me/` which gets current user
        - Regular users cannot view other users' profiles

        **Security:**
        - This endpoint is ADMIN-ONLY
        - Regular users will receive 403 Forbidden
        - Use `/auth/users/me/` for current user profile instead
        """,
        examples=[
            OpenApiExample(
                'Success Response',
                value={
                    'id': 1,
                    'email': 'user@example.com',
                    'username': 'johndoe',
                    'email_verified': True,
                    'is_2fa_enabled': False
                },
                response_only=True,
                status_codes=['200'],
            ),
        ],
        responses={
            200: OpenApiResponse(description='User profile retrieved successfully'),
            401: OpenApiResponse(description='Unauthorized - Missing or invalid access token'),
            403: OpenApiResponse(description='Forbidden - Insufficient permissions to view this user'),
            404: OpenApiResponse(description='Not Found - User with this ID does not exist'),
        }
    )
    def retrieve(self, request, *args, **kwargs):
        """Get user by ID."""
        return super().retrieve(request, *args, **kwargs)

    @extend_schema(
        tags=['User Management'],
        summary='Update user by ID (Admin only - full update)',
        description="""
        Fully update a user's profile information by their user ID (PUT method).

        **What This Does:**
        - Replaces all fields of the user profile
        - Requires all required fields to be provided
        - Uses PUT method (full replacement)

        **Prerequisites:**
        - **Admin privileges required** (is_staff=True)
        - Must be authenticated with admin account

        **Common Use Cases:**
        - Admin user management
        - Bulk user updates
        - Profile synchronization

        **Important Notes:**
        - All required fields must be provided
        - Missing fields will be set to default/null
        - Use PATCH for partial updates instead
        - Cannot change password via this endpoint (use set_password)

        **Security:**
        - This endpoint is ADMIN-ONLY
        - Regular users will receive 403 Forbidden
        - Use `/auth/users/me/` to update your own profile
        - Audit log recommended for user modifications
        """,
        request=inline_serializer(
            name='UserUpdateRequest',
            fields={
                'email': serializers.EmailField(help_text='Email address'),
                'username': serializers.CharField(help_text='Username'),
            }
        ),
        examples=[
            OpenApiExample(
                'Update User Request',
                value={
                    'email': 'updated@example.com',
                    'username': 'updateduser'
                },
                request_only=True,
            ),
        ],
        responses={
            200: OpenApiResponse(description='User updated successfully'),
            400: OpenApiResponse(description='Bad Request - Validation errors'),
            401: OpenApiResponse(description='Unauthorized - Missing or invalid access token'),
            403: OpenApiResponse(description='Forbidden - Insufficient permissions to update this user'),
            404: OpenApiResponse(description='Not Found - User with this ID does not exist'),
        }
    )
    def update(self, request, *args, **kwargs):
        """Update user by ID (PUT)."""
        return super().update(request, *args, **kwargs)

    @extend_schema(
        tags=['User Management'],
        summary='Partially update user by ID (Admin only)',
        description="""
        Partially update a user's profile information by their user ID (PATCH method).

        **What This Does:**
        - Updates only the fields provided
        - Other fields remain unchanged
        - Uses PATCH method (partial update)

        **Prerequisites:**
        - **Admin privileges required** (is_staff=True)
        - Must be authenticated with admin account

        **Common Use Cases:**
        - Update specific user fields
        - Admin user management
        - Profile field corrections

        **Important Notes:**
        - Only provided fields are updated
        - More flexible than PUT (full update)
        - Cannot change password via this endpoint (use set_password)

        **Difference from PUT:**
        - PATCH: Only updates provided fields
        - PUT: Replaces entire resource (all fields required)

        **Security:**
        - This endpoint is ADMIN-ONLY
        - Regular users will receive 403 Forbidden
        - Use `/auth/users/me/` to update your own profile
        - Audit log recommended for user modifications
        """,
        request=inline_serializer(
            name='UserPartialUpdateRequest',
            fields={
                'email': serializers.EmailField(required=False, help_text='Email address (optional)'),
                'username': serializers.CharField(required=False, help_text='Username (optional)'),
            }
        ),
        examples=[
            OpenApiExample(
                'Partial Update User Request',
                value={'email': 'newemail@example.com'},
                request_only=True,
            ),
        ],
        responses={
            200: OpenApiResponse(description='User updated successfully'),
            400: OpenApiResponse(description='Bad Request - Validation errors'),
            401: OpenApiResponse(description='Unauthorized - Missing or invalid access token'),
            403: OpenApiResponse(description='Forbidden - Insufficient permissions to update this user'),
            404: OpenApiResponse(description='Not Found - User with this ID does not exist'),
        }
    )
    def partial_update(self, request, *args, **kwargs):
        """Partially update user by ID (PATCH)."""
        return super().partial_update(request, *args, **kwargs)

    @extend_schema(
        tags=['User Management'],
        summary='Delete user by ID (Admin only)',
        description="""
        Delete a user account by their user ID.

        **What This Does:**
        - Permanently deletes the user account
        - Cascade deletes related data (tokens, 2FA settings, etc.)
        - Cannot be undone

        **Prerequisites:**
        - **Admin privileges required** (is_staff=True)
        - Must be authenticated with admin account

        **Common Use Cases:**
        - Admin user management
        - Account removal requests
        - Cleanup of inactive/spam accounts
        - Ban enforcement

        **Important Notes:**
        - Deletion is permanent and irreversible
        - Related data (tokens, 2FA settings, etc.) will be deleted
        - Consider soft-delete for data retention
        - All JWT tokens for user are automatically invalidated

        **Security:**
        - This endpoint is ADMIN-ONLY
        - Regular users will receive 403 Forbidden
        - Use `/auth/users/me/` to delete your own account
        - Audit log strongly recommended
        - Consider GDPR/data retention policies

        **After Deletion:**
        - User cannot login
        - All tokens are invalidated
        - Email/username become available for reuse
        - Related data is deleted (cascading)
        """,
        responses={
            204: OpenApiResponse(description='User deleted successfully (no content returned)'),
            401: OpenApiResponse(description='Unauthorized - Missing or invalid access token'),
            403: OpenApiResponse(description='Forbidden - Insufficient permissions to delete this user'),
            404: OpenApiResponse(description='Not Found - User with this ID does not exist'),
        }
    )
    def destroy(self, request, *args, **kwargs):
        """Delete user by ID."""
        return super().destroy(request, *args, **kwargs)

    @extend_schema(
        methods=['GET'],
        tags=['User Management'],
        summary='Get current user profile',
        description="""
        Retrieve the authenticated user's profile information.

        **What You Get:**
        - User ID
        - Email address
        - Username
        - Email verification status
        - 2FA enabled status
        - Any other profile fields

        **Prerequisites:**
        - Must be authenticated (Bearer token in Authorization header)

        **Use Cases:**
        - Display user profile in UI
        - Check email verification status
        - Check 2FA status
        - Get user ID for other operations
        """,
        examples=[
            OpenApiExample(
                'Success Response',
                value={
                    'id': 1,
                    'email': 'user@example.com',
                    'username': 'johndoe',
                    'email_verified': True,
                    'is_2fa_enabled': False
                },
                response_only=True,
                status_codes=['200'],
            ),
        ],
        responses={
            200: OpenApiResponse(description='User profile retrieved successfully'),
            401: OpenApiResponse(description='Unauthorized - Missing or invalid access token'),
        }
    )
    @extend_schema(
        methods=['PUT'],
        tags=['User Management'],
        summary='Update current user profile (full update)',
        description="""
        Fully update the authenticated user's profile information (PUT method).

        **What This Does:**
        - Replaces all fields of your profile
        - Requires all required fields to be provided
        - Uses PUT method (full replacement)

        **Common Use Cases:**
        - Complete profile update
        - Profile synchronization
        - Change email or username

        **Important Notes:**
        - Must provide all required fields
        - Missing optional fields will be cleared
        - Use PATCH for partial updates instead
        - Cannot change password via this endpoint (use `/auth/users/set_password/`)

        **Prerequisites:**
        - Must be authenticated (Bearer token in Authorization header)

        **Difference from PATCH:**
        - PUT: Replaces entire profile (all required fields needed)
        - PATCH: Updates only provided fields
        """,
        request=inline_serializer(
            name='UserMeUpdateRequest',
            fields={
                'email': serializers.EmailField(help_text='Email address'),
                'username': serializers.CharField(help_text='Username'),
            }
        ),
        examples=[
            OpenApiExample(
                'Update Profile Request',
                value={
                    'email': 'newemail@example.com',
                    'username': 'newusername'
                },
                request_only=True,
            ),
        ],
        responses={
            200: OpenApiResponse(description='Profile updated successfully'),
            400: OpenApiResponse(description='Bad Request - Validation errors'),
            401: OpenApiResponse(description='Unauthorized - Missing or invalid access token'),
        }
    )
    @extend_schema(
        methods=['PATCH'],
        tags=['User Management'],
        summary='Partially update current user profile',
        description="""
        Partially update the authenticated user's profile information (PATCH method).

        **What This Does:**
        - Updates only the fields provided
        - Other fields remain unchanged
        - Uses PATCH method (partial update)

        **Common Use Cases:**
        - Update email only
        - Update username only
        - Update any single profile field

        **Important Notes:**
        - Only provided fields are updated
        - More flexible than PUT (full update)
        - Cannot change password via this endpoint (use `/auth/users/set_password/`)

        **Prerequisites:**
        - Must be authenticated (Bearer token in Authorization header)

        **Difference from PUT:**
        - PATCH: Updates only provided fields (recommended)
        - PUT: Replaces entire profile (all required fields needed)
        """,
        request=inline_serializer(
            name='UserMePartialUpdateRequest',
            fields={
                'email': serializers.EmailField(required=False, help_text='Email address (optional)'),
                'username': serializers.CharField(required=False, help_text='Username (optional)'),
            }
        ),
        examples=[
            OpenApiExample(
                'Partial Update Profile Request',
                value={'email': 'newemail@example.com'},
                request_only=True,
            ),
        ],
        responses={
            200: OpenApiResponse(description='Profile updated successfully'),
            400: OpenApiResponse(description='Bad Request - Validation errors'),
            401: OpenApiResponse(description='Unauthorized - Missing or invalid access token'),
        }
    )
    @extend_schema(
        methods=['DELETE'],
        tags=['User Management'],
        summary='Delete current user account',
        description="""
        Delete the authenticated user's own account.

        **What This Does:**
        - Permanently deletes your account
        - Removes all associated data
        - Cannot be undone
        - Immediately invalidates all JWT tokens

        **Common Use Cases:**
        - User-initiated account deletion
        - GDPR "right to be forgotten" requests
        - Account closure

        **Important Notes:**
        - Deletion is permanent and irreversible
        - All related data (2FA settings, tokens, etc.) will be deleted
        - User will be immediately logged out
        - Email/username become available for reuse

        **Prerequisites:**
        - Must be authenticated (Bearer token in Authorization header)

        **Security Considerations:**
        - Consider adding confirmation step in frontend
        - May want to require password confirmation
        - Consider data export before deletion (GDPR)
        - All JWT tokens are automatically invalidated

        **After Deletion:**
        - Cannot login anymore
        - All tokens are invalidated
        - All data is permanently removed
        - Email can be used to create new account
        """,
        responses={
            204: OpenApiResponse(description='Account deleted successfully (no content returned)'),
            401: OpenApiResponse(description='Unauthorized - Missing or invalid access token'),
        }
    )
    def me(self, request, *args, **kwargs):
        """Handle current user profile operations (GET, PUT, PATCH, DELETE)."""
        return super().me(request, *args, **kwargs)

    @extend_schema(
        tags=['User Management'],
        summary='Activate user account',
        description="""
        Activate a user account using the UID and token from activation email.

        **Activation Flow:**
        1. User registers at `/auth/users/`
        2. System sends activation email with uid and token
        3. User clicks link or frontend calls this endpoint
        4. Account becomes active
        5. User can now login

        **Email Link Format:**
        - Link in email: `{FRONTEND_URL}/activate/{uid}/{token}`
        - Frontend should extract uid/token and call this endpoint

        **Important Notes:**
        - Token is single-use only
        - Token expires after 24 hours (configurable)
        - Already active accounts will return error
        - After activation, login at `/auth/jwt/create/`

        **Common Errors:**
        - Invalid uid/token: Token expired or already used
        - Already activated: Account is already active
        """,
        request=inline_serializer(
            name='ActivationRequest',
            fields={
                'uid': serializers.CharField(help_text='User ID from activation email'),
                'token': serializers.CharField(help_text='Activation token from email'),
            }
        ),
        examples=[
            OpenApiExample(
                'Activation Request',
                value={
                    'uid': 'MQ',
                    'token': 'abc123-def456-ghi789'
                },
                request_only=True,
            ),
        ],
        responses={
            204: OpenApiResponse(description='Account activated successfully (no content returned)'),
            400: OpenApiResponse(
                description='Bad Request - Invalid uid/token or account already active',
                response=inline_serializer(
                    name='ActivationErrorResponse',
                    fields={
                        'detail': serializers.CharField(help_text='Error message'),
                    }
                )
            ),
        }
    )
    def activation(self, request, *args, **kwargs):
        """Activate user account with uid and token."""
        return super().activation(request, *args, **kwargs)

    @extend_schema(
        tags=['User Management'],
        summary='Resend activation email',
        description="""
        Resend the account activation email to the user.

        **Use Cases:**
        - User didn't receive activation email
        - Activation link expired
        - Email was accidentally deleted

        **What Happens:**
        1. Validates the email exists in system
        2. Checks if account is already active
        3. Generates new uid and token
        4. Sends new activation email

        **Important Notes:**
        - Only works for inactive accounts
        - Previous activation links become invalid
        - New token expires in 24 hours
        - Rate limiting may apply

        **After Receiving Email:**
        - Click activation link or call `/auth/users/activation/`
        """,
        request=inline_serializer(
            name='ResendActivationRequest',
            fields={
                'email': serializers.EmailField(help_text='Email address of account to activate'),
            }
        ),
        examples=[
            OpenApiExample(
                'Resend Activation Request',
                value={'email': 'user@example.com'},
                request_only=True,
            ),
        ],
        responses={
            204: OpenApiResponse(description='Activation email sent successfully (no content returned)'),
            400: OpenApiResponse(
                description='Bad Request - Account already active or email not found',
                response=inline_serializer(
                    name='ResendActivationErrorResponse',
                    fields={
                        'detail': serializers.CharField(help_text='Error message'),
                    }
                )
            ),
        }
    )
    def resend_activation(self, request, *args, **kwargs):
        """Resend activation email to user."""
        return super().resend_activation(request, *args, **kwargs)

    @extend_schema(
        tags=['User Management'],
        summary='Request password reset',
        description="""
        Request a password reset email for forgotten password.

        **Password Reset Flow:**
        1. Call this endpoint with email
        2. System sends password reset email
        3. User clicks link in email
        4. Frontend calls `/auth/users/reset_password_confirm/` with uid/token/new password
        5. Password is changed and all tokens are blacklisted

        **Email Link Format:**
        - Link in email: `{FRONTEND_URL}/password/reset/confirm/{uid}/{token}`
        - Frontend should show password reset form
        - Frontend extracts uid/token and submits with new password

        **Important Notes:**
        - Always returns 204 even if email doesn't exist (security)
        - Token expires after 24 hours (configurable)
        - Token is single-use only
        - After reset, all JWT tokens are blacklisted

        **Security:**
        - Doesn't reveal if email exists in system
        - Rate limiting prevents abuse
        - Tokens are cryptographically secure
        """,
        request=inline_serializer(
            name='ResetPasswordRequest',
            fields={
                'email': serializers.EmailField(help_text='Email address of account to reset'),
            }
        ),
        examples=[
            OpenApiExample(
                'Password Reset Request',
                value={'email': 'user@example.com'},
                request_only=True,
            ),
        ],
        responses={
            204: OpenApiResponse(description='Password reset email sent (or silently ignored if email not found)'),
        }
    )
    def reset_password(self, request, *args, **kwargs):
        """Send password reset email."""
        return super().reset_password(request, *args, **kwargs)

    @extend_schema(
        tags=['User Management'],
        summary='Confirm password reset with new password',
        description="""
        Complete the password reset process with uid, token, and new password.

        **Reset Confirmation Flow:**
        1. User received password reset email
        2. Clicked link: `{FRONTEND_URL}/password/reset/confirm/{uid}/{token}`
        3. Frontend shows password reset form
        4. User enters new password
        5. Frontend calls this endpoint with uid, token, and new password
        6. Password is changed
        7. **ALL JWT tokens are automatically blacklisted**
        8. User must login again with new password

        **Important Notes:**
        - Token is single-use only
        - Token expires after 24 hours
        - New password must meet validation requirements
        - All existing sessions are invalidated (tokens blacklisted)
        - User must login at `/auth/jwt/create/` after reset

        **Security:**
        - Forces re-authentication after password reset
        - Invalidates all existing sessions
        - Prevents unauthorized access if password was compromised
        - This happens ALWAYS, regardless of settings

        **After Success:**
        1. All JWT tokens are blacklisted
        2. User receives password changed confirmation email
        3. User must login with new password
        """,
        request=inline_serializer(
            name='ResetPasswordConfirmRequest',
            fields={
                'uid': serializers.CharField(help_text='User ID from reset email'),
                'token': serializers.CharField(help_text='Reset token from email'),
                'new_password': serializers.CharField(help_text='New password to set'),
            }
        ),
        examples=[
            OpenApiExample(
                'Password Reset Confirm Request',
                value={
                    'uid': 'MQ',
                    'token': 'abc123-def456-ghi789',
                    'new_password': 'NewSecurePass123!'
                },
                request_only=True,
            ),
        ],
        responses={
            204: OpenApiResponse(description='Password reset successful. All JWT tokens blacklisted. Login required.'),
            400: OpenApiResponse(
                description='Bad Request - Invalid uid/token or password validation failed',
                response=inline_serializer(
                    name='ResetPasswordConfirmErrorResponse',
                    fields={
                        'uid': serializers.ListField(help_text='UID validation errors'),
                        'token': serializers.ListField(help_text='Token validation errors'),
                        'new_password': serializers.ListField(help_text='Password validation errors'),
                    }
                )
            ),
        }
    )
    def reset_password_confirm(self, request, *args, **kwargs):
        """
        Override password reset confirm to blacklist all user tokens.

        After a successful password reset, all existing JWT refresh tokens
        are blacklisted to force re-authentication for security purposes.
        This ALWAYS happens on password reset, regardless of settings.
        """
        # Call parent method to handle password reset
        response = super().reset_password_confirm(request, *args, **kwargs)

        # If password reset was successful, blacklist all tokens
        if response.status_code == status.HTTP_204_NO_CONTENT:
            # Extract user from serializer
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                user = serializer.user
                blacklist_user_tokens(user)

        return response

    @extend_schema(
        tags=['User Management'],
        summary='Change password (authenticated user)',
        description="""
        Change the password for the currently authenticated user.

        **Password Change Flow:**
        1. User must be logged in (authenticated)
        2. Provide current password and new password
        3. Password is changed
        4. **Optional:** JWT tokens may be blacklisted (if enabled in settings)
        5. User receives password changed confirmation email

        **Token Blacklisting:**
        - Controlled by `BLACKLIST_TOKENS_ON_PASSWORD_CHANGE` setting
        - If `True`: All JWT tokens are blacklisted, user must login again
        - If `False`: Current session remains active (default)

        **Important Notes:**
        - Must provide correct current password
        - New password must meet validation requirements
        - New password cannot be same as current password
        - After change, check if you need to re-login

        **Prerequisites:**
        - Must be authenticated (Bearer token in Authorization header)

        **Difference from Password Reset:**
        - This requires current password (user is logged in)
        - Password reset is for forgotten passwords (uses email)
        - Password reset ALWAYS blacklists tokens
        - This only blacklists if setting is enabled

        **Security:**
        - Requires current password to prevent unauthorized changes
        - Password validation enforced
        - Email confirmation sent
        """,
        request=inline_serializer(
            name='SetPasswordRequest',
            fields={
                'current_password': serializers.CharField(help_text='Current password for verification'),
                'new_password': serializers.CharField(help_text='New password to set'),
            }
        ),
        examples=[
            OpenApiExample(
                'Change Password Request',
                value={
                    'current_password': 'OldPass123!',
                    'new_password': 'NewSecurePass123!'
                },
                request_only=True,
            ),
        ],
        responses={
            204: OpenApiResponse(description='Password changed successfully. Check BLACKLIST_TOKENS_ON_PASSWORD_CHANGE setting to see if re-login required.'),
            400: OpenApiResponse(
                description='Bad Request - Validation errors',
                response=inline_serializer(
                    name='SetPasswordErrorResponse',
                    fields={
                        'current_password': serializers.ListField(help_text='Current password errors'),
                        'new_password': serializers.ListField(help_text='New password validation errors'),
                    }
                )
            ),
            401: OpenApiResponse(description='Unauthorized - Missing or invalid access token'),
        }
    )
    def set_password(self, request, *args, **kwargs):
        """
        Override password change to conditionally blacklist tokens.

        After a successful password change, JWT refresh tokens are blacklisted
        ONLY if BLACKLIST_TOKENS_ON_PASSWORD_CHANGE setting is True.
        """
        # Call parent method to handle password change
        response = super().set_password(request, *args, **kwargs)

        # If password change was successful and setting is enabled
        if (response.status_code == status.HTTP_204_NO_CONTENT and
            getattr(settings, 'BLACKLIST_TOKENS_ON_PASSWORD_CHANGE', False)):
            # Blacklist all tokens for this user
            blacklist_user_tokens(request.user)

        return response
