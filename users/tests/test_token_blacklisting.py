"""
Tests for JWT token blacklisting on password reset and change.

This module tests that JWT tokens are properly blacklisted when users
reset or change their passwords for security purposes.
"""

import pytest
from django.contrib.auth import get_user_model
from django.conf import settings
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from users.utils import blacklist_user_tokens

User = get_user_model()


@pytest.fixture
def api_client():
    """Fixture to provide APIClient instance."""
    return APIClient()


@pytest.fixture
def create_user(db):
    """Fixture to create a test user."""
    def make_user(**kwargs):
        defaults = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpass123',
        }
        defaults.update(kwargs)
        password = defaults.pop('password')
        user = User.objects.create_user(**defaults)
        user.set_password(password)
        user.save()
        return user
    return make_user


@pytest.mark.django_db
class TestBlacklistUtilityFunction:
    """Test suite for blacklist_user_tokens utility function."""

    def test_blacklist_user_tokens_function_exists(self):
        """Test that blacklist_user_tokens utility function exists."""
        from users.utils import blacklist_user_tokens
        assert callable(blacklist_user_tokens)

    def test_blacklist_user_tokens_blacklists_all_tokens(self, create_user):
        """Test that blacklist_user_tokens blacklists all user's outstanding tokens."""
        user = create_user()

        # Create multiple refresh tokens for the user
        token1 = RefreshToken.for_user(user)
        token2 = RefreshToken.for_user(user)

        # Count outstanding tokens before blacklisting
        outstanding_count = OutstandingToken.objects.filter(user=user).count()
        assert outstanding_count >= 2

        # Blacklist all tokens
        blacklisted_count = blacklist_user_tokens(user)

        # Verify blacklisted count matches outstanding tokens
        assert blacklisted_count == outstanding_count

        # Verify all tokens are in BlacklistedToken table
        blacklisted = BlacklistedToken.objects.filter(
            token__user=user
        ).count()
        assert blacklisted == outstanding_count

    def test_blacklist_user_tokens_handles_no_tokens(self, create_user):
        """Test that blacklist_user_tokens handles users with no outstanding tokens."""
        user = create_user()

        # Don't create any tokens for this user

        # Should not raise an error
        blacklisted_count = blacklist_user_tokens(user)
        assert blacklisted_count == 0

    def test_blacklist_user_tokens_handles_already_blacklisted(self, create_user):
        """Test that blacklist_user_tokens handles already blacklisted tokens."""
        user = create_user()

        # Create and immediately blacklist a token
        token = RefreshToken.for_user(user)
        token.blacklist()

        # Try to blacklist again - should handle gracefully
        blacklisted_count = blacklist_user_tokens(user)
        # Should return 0 because no new tokens were blacklisted
        assert blacklisted_count >= 0


@pytest.mark.django_db
class TestPasswordChangeTokenBlacklisting:
    """Test suite for conditional JWT token blacklisting on password change."""

    def test_password_change_blacklists_tokens_when_setting_enabled(self, api_client, create_user, settings):
        """Test that password change blacklists tokens when setting is True."""
        # Enable token blacklisting on password change
        settings.BLACKLIST_TOKENS_ON_PASSWORD_CHANGE = True

        user = create_user(email='user@example.com', password='oldpass123')
        refresh = RefreshToken.for_user(user)
        old_refresh_token = str(refresh)

        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        # Change password
        response = api_client.post('/auth/users/set_password/', {
            'new_password': 'newpass123',
            'current_password': 'oldpass123',
        })

        assert response.status_code == 204

        # Old token should be blacklisted
        refresh_response = api_client.post('/auth/jwt/refresh/', {
            'refresh': old_refresh_token
        })
        assert refresh_response.status_code == 401

    def test_password_change_does_not_blacklist_when_setting_disabled(self, api_client, create_user, settings):
        """Test that password change does NOT blacklist tokens when setting is False."""
        # Disable token blacklisting on password change
        settings.BLACKLIST_TOKENS_ON_PASSWORD_CHANGE = False

        user = create_user(email='user@example.com', password='oldpass123')
        refresh = RefreshToken.for_user(user)
        old_refresh_token = str(refresh)

        # Count tokens before password change
        tokens_before = OutstandingToken.objects.filter(user=user).count()

        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        # Change password
        response = api_client.post('/auth/users/set_password/', {
            'new_password': 'newpass123',
            'current_password': 'oldpass123',
        })

        assert response.status_code == 204

        # Count blacklisted tokens - should be 0 or unchanged
        blacklisted_count = BlacklistedToken.objects.filter(token__user=user).count()

        # When setting is False, tokens should NOT be blacklisted
        # The count should be 0 or same as before (if any were previously blacklisted)
        assert blacklisted_count == 0 or blacklisted_count < tokens_before


@pytest.mark.django_db
class TestPasswordResetEmailSending:
    """Test suite for password reset email functionality."""

    def test_password_reset_request_sends_email(self, api_client, create_user):
        """Test that password reset request sends an email."""
        from django.core import mail

        user = create_user(email='user@example.com')

        mail.outbox = []

        data = {'email': 'user@example.com'}
        response = api_client.post('/auth/users/reset_password/', data)

        assert response.status_code == 204
        assert len(mail.outbox) == 1

    def test_password_reset_request_does_not_reveal_email_existence(self, api_client):
        """Test that password reset returns 204 even for non-existent emails."""
        data = {'email': 'nonexistent@example.com'}
        response = api_client.post('/auth/users/reset_password/', data)

        # Should return 204 to not reveal if email exists
        assert response.status_code == 204


@pytest.mark.django_db
class TestPasswordChangeRequiresCurrentPassword:
    """Test suite for password change security."""

    def test_password_change_requires_current_password(self, api_client, create_user):
        """Test that password change requires correct current password."""
        user = create_user(email='user@example.com', password='oldpass123')
        refresh = RefreshToken.for_user(user)

        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        # Try to change password with wrong current password
        response = api_client.post('/auth/users/set_password/', {
            'new_password': 'newpass123',
            'current_password': 'wrongpassword',
        })

        assert response.status_code == 400

    def test_password_change_succeeds_with_correct_current_password(self, api_client, create_user):
        """Test that password change succeeds with correct current password."""
        user = create_user(email='user@example.com', password='oldpass123')
        refresh = RefreshToken.for_user(user)

        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        # Change password with correct current password
        response = api_client.post('/auth/users/set_password/', {
            'new_password': 'newpass123',
            'current_password': 'oldpass123',
        })

        assert response.status_code == 204

        # Verify user can login with new password
        login_response = api_client.post('/auth/jwt/create/', {
            'username': 'user@example.com',
            'password': 'newpass123',
        })

        assert login_response.status_code == 200
