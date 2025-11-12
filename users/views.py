"""
Views for user authentication and profile management.

Provides custom views for logout functionality with token blacklisting.
"""

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from drf_spectacular.utils import extend_schema
from .serializers import LogoutSerializer


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
