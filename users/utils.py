"""
Utility functions for user management.

This module provides helper functions for user-related operations,
particularly JWT token management.
"""

from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken


def blacklist_user_tokens(user):
    """
    Blacklist all outstanding JWT refresh tokens for a user.

    This function is used for security purposes when a user's password is
    reset or changed. It ensures that all existing JWT tokens are invalidated,
    forcing the user to re-authenticate.

    Args:
        user: The User instance whose tokens should be blacklisted

    Returns:
        int: The number of tokens that were blacklisted

    Example:
        >>> from django.contrib.auth import get_user_model
        >>> User = get_user_model()
        >>> user = User.objects.get(email='user@example.com')
        >>> count = blacklist_user_tokens(user)
        >>> print(f"Blacklisted {count} tokens")
    """
    # Get all outstanding tokens for this user
    outstanding_tokens = OutstandingToken.objects.filter(user=user)

    blacklisted_count = 0

    for outstanding_token in outstanding_tokens:
        # Check if token is already blacklisted
        if not BlacklistedToken.objects.filter(token=outstanding_token).exists():
            # Create blacklist entry
            BlacklistedToken.objects.create(token=outstanding_token)
            blacklisted_count += 1

    return blacklisted_count
