"""
Views for user authentication and profile management.

Provides custom views for logout functionality with token blacklisting,
and custom password management views with JWT token blacklisting.
"""

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from drf_spectacular.utils import extend_schema
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
        request=LogoutSerializer,
        responses={
            204: None,
            400: {'description': 'Bad Request - Invalid or missing refresh token'}
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
