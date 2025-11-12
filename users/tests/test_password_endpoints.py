"""
Tests for password management API endpoints.

This module tests the Djoser password reset, password change, and email
activation endpoints to ensure they work correctly with proper validation.
"""

import pytest
from django.core import mail
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

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
class TestPasswordResetEndpoints:
    """Test suite for password reset endpoints."""

    def test_reset_password_accepts_email_and_returns_204(self, api_client, create_user):
        """Test POST /auth/users/reset_password/ accepts email and returns 204."""
        user = create_user(email='user@example.com')

        data = {'email': 'user@example.com'}
        response = api_client.post('/auth/users/reset_password/', data)

        assert response.status_code == 204

    def test_reset_password_does_not_reveal_if_email_exists(self, api_client):
        """Test POST /auth/users/reset_password/ doesn't reveal if email exists."""
        # Non-existent email should still return 204
        data = {'email': 'nonexistent@example.com'}
        response = api_client.post('/auth/users/reset_password/', data)

        assert response.status_code == 204

    def test_reset_password_sends_email(self, api_client, create_user):
        """Test password reset sends email to user."""
        user = create_user(email='user@example.com')

        mail.outbox = []

        data = {'email': 'user@example.com'}
        api_client.post('/auth/users/reset_password/', data)

        assert len(mail.outbox) == 1
        assert 'user@example.com' in mail.outbox[0].to


@pytest.mark.django_db
class TestPasswordChangeEndpoint:
    """Test suite for password change endpoint."""

    def test_set_password_requires_current_password(self, api_client, create_user):
        """Test POST /auth/users/set_password/ requires current_password."""
        user = create_user(email='user@example.com', password='oldpass123')
        refresh = RefreshToken.for_user(user)
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        # Missing current_password
        data = {
            'new_password': 'newpass123',
        }
        response = api_client.post('/auth/users/set_password/', data)

        assert response.status_code == 400

    def test_set_password_rejects_incorrect_current_password(self, api_client, create_user):
        """Test POST /auth/users/set_password/ rejects incorrect current_password."""
        user = create_user(email='user@example.com', password='oldpass123')
        refresh = RefreshToken.for_user(user)
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        data = {
            'new_password': 'newpass123',
            'current_password': 'wrongpassword',
        }
        response = api_client.post('/auth/users/set_password/', data)

        assert response.status_code == 400

    def test_set_password_updates_password_with_correct_current_password(self, api_client, create_user):
        """Test POST /auth/users/set_password/ updates password with correct current_password."""
        user = create_user(email='user@example.com', password='oldpass123')
        refresh = RefreshToken.for_user(user)
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        data = {
            'new_password': 'newpass123',
            'current_password': 'oldpass123',
        }
        response = api_client.post('/auth/users/set_password/', data)

        assert response.status_code == 204

        # Verify new password works
        login_response = api_client.post('/auth/jwt/create/', {
            'username': 'user@example.com',
            'password': 'newpass123',
        })

        assert login_response.status_code == 200

    def test_set_password_requires_authentication(self, api_client):
        """Test POST /auth/users/set_password/ requires authentication."""
        # Don't set credentials

        data = {
            'new_password': 'newpass123',
            'current_password': 'oldpass123',
        }
        response = api_client.post('/auth/users/set_password/', data)

        assert response.status_code == 401


@pytest.mark.django_db
class TestEmailActivationEndpoints:
    """Test suite for email activation endpoints."""

    def test_activation_email_sent_on_registration(self, api_client, settings):
        """Test activation email is sent when user registers."""
        mail.outbox = []

        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'securepass123',
        }
        response = api_client.post('/auth/users/', data)

        assert response.status_code == 201

        # Check if activation email was sent
        if settings.DJOSER.get('SEND_ACTIVATION_EMAIL'):
            assert len(mail.outbox) >= 1

    def test_resend_activation_endpoint_exists(self, api_client):
        """Test POST /auth/users/resend_activation/ endpoint exists."""
        # Just test that the endpoint responds (doesn't return 404)
        data = {'email': 'test@example.com'}
        response = api_client.post('/auth/users/resend_activation/', data)

        # Should return 204 or 400, not 404
        assert response.status_code in [204, 400]


@pytest.mark.django_db
class TestPasswordValidation:
    """Test suite for password validation."""

    def test_password_reset_with_weak_password_returns_validation_error(self, api_client, create_user):
        """Test password reset with weak password returns validation error."""
        user = create_user(email='user@example.com')
        refresh = RefreshToken.for_user(user)
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        # Try to set a weak password (too short)
        data = {
            'new_password': '123',  # Too short
            'current_password': 'testpass123',
        }
        response = api_client.post('/auth/users/set_password/', data)

        # Should return 400 with validation error
        assert response.status_code == 400

    def test_password_change_with_numeric_only_password_returns_error(self, api_client, create_user):
        """Test password change with numeric-only password returns validation error."""
        user = create_user(email='user@example.com', password='testpass123')
        refresh = RefreshToken.for_user(user)
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        # Try to set a numeric-only password
        data = {
            'new_password': '12345678',  # Only numbers
            'current_password': 'testpass123',
        }
        response = api_client.post('/auth/users/set_password/', data)

        # Should return 400 with validation error
        assert response.status_code == 400

    def test_password_change_with_common_password_returns_error(self, api_client, create_user):
        """Test password change with common password returns validation error."""
        user = create_user(email='user@example.com', password='testpass123')
        refresh = RefreshToken.for_user(user)
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        # Try to set a common password
        data = {
            'new_password': 'password',  # Too common
            'current_password': 'testpass123',
        }
        response = api_client.post('/auth/users/set_password/', data)

        # Should return 400 with validation error
        assert response.status_code == 400


@pytest.mark.django_db
class TestErrorResponseFormat:
    """Test suite for error response formats."""

    def test_invalid_current_password_returns_400_with_error_details(self, api_client, create_user):
        """Test that incorrect current password returns 400 with error details."""
        user = create_user(email='user@example.com', password='testpass123')
        refresh = RefreshToken.for_user(user)
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        data = {
            'new_password': 'newpass123',
            'current_password': 'wrongpassword',
        }
        response = api_client.post('/auth/users/set_password/', data)

        assert response.status_code == 400
        assert 'current_password' in response.data or 'detail' in response.data

    def test_unauthenticated_request_returns_401(self, api_client):
        """Test that unauthenticated request returns 401."""
        data = {
            'new_password': 'newpass123',
            'current_password': 'oldpass123',
        }
        response = api_client.post('/auth/users/set_password/', data)

        assert response.status_code == 401

    def test_error_messages_dont_leak_sensitive_information(self, api_client):
        """Test that error messages don't leak sensitive information."""
        # Request password reset for non-existent email
        data = {'email': 'nonexistent@example.com'}
        response = api_client.post('/auth/users/reset_password/', data)

        # Should return 204 (not 404) to not reveal email existence
        assert response.status_code == 204
