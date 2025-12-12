# middleware.py

from django.utils.deprecation import MiddlewareMixin
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth.models import AnonymousUser
import threading

# Thread-local storage to store user for each request
_thread_local = threading.local()


def get_current_user():
    user = getattr(_thread_local, "user", None)
    if isinstance(user, AnonymousUser):
        return None  # Return None if the user is not authenticated
    return user


class CurrentUserMiddleware(MiddlewareMixin):
    """
    Middleware to store the current user in thread-local storage.
    Handles JWT-based authentication for APIs.
    """

    def process_request(self, request):
        user = AnonymousUser()  # Default to AnonymousUser

        # Try to get the user from JWT authentication
        try:
            jwt_auth = JWTAuthentication()
            user_auth_tuple = jwt_auth.authenticate(request)  # Authenticate using JWT
            if user_auth_tuple is not None:
                user, _ = user_auth_tuple  # Extract the user if authentication succeeds

        except InvalidToken as e:
            # Attach an attribute on the request to signal an invalid token
            request.invalid_token = {
                "error": "Token is invalid or expired",
                "detail": str(e),
            }
        except Exception as e:
            # Handle any other exceptions and attach the error to the request
            request.invalid_token = {
                "error": "An error occurred during authentication",
                "detail": str(e),
            }

        # Store the authenticated user in thread-local storage
        _thread_local.user = user

    def process_view(self, request, view_func, view_args, view_kwargs):
        # Check if there's an invalid token and return an appropriate response in the view
        if hasattr(request, "invalid_token"):
            return None  # Let the view handle it or a custom response
