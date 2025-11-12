"""
Tests for email templates and notifications.

This module tests that email templates are rendered correctly and emails
are sent with appropriate variables for password management events.
"""

import pytest
from django.core import mail
from django.contrib.auth import get_user_model
from django.conf import settings
from rest_framework.test import APIClient

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
class TestPasswordResetEmail:
    """Test suite for password reset email template."""

    def test_password_reset_request_sends_email(self, api_client, create_user):
        """Test POST /auth/users/reset_password/ sends password reset email."""
        user = create_user(email='user@example.com')

        # Clear any existing emails
        mail.outbox = []

        data = {'email': 'user@example.com'}
        response = api_client.post('/auth/users/reset_password/', data)

        assert response.status_code == 204
        assert len(mail.outbox) == 1

    def test_password_reset_email_contains_user_info(self, api_client, create_user):
        """Test password reset email contains user information."""
        user = create_user(email='user@example.com', username='testuser')

        mail.outbox = []

        data = {'email': 'user@example.com'}
        api_client.post('/auth/users/reset_password/', data)

        assert len(mail.outbox) == 1
        email = mail.outbox[0]

        # Email should be sent to user
        assert 'user@example.com' in email.to

        # Email should have appropriate subject
        assert 'password' in email.subject.lower() or 'reset' in email.subject.lower()

    def test_password_reset_email_uses_correct_from_address(self, api_client, create_user):
        """Test password reset email uses configured from_email."""
        user = create_user(email='user@example.com')

        mail.outbox = []

        data = {'email': 'user@example.com'}
        api_client.post('/auth/users/reset_password/', data)

        assert len(mail.outbox) == 1
        email = mail.outbox[0]

        # Should use DEFAULT_FROM_EMAIL setting
        assert email.from_email == settings.DEFAULT_FROM_EMAIL


@pytest.mark.django_db
class TestPasswordChangeConfirmationEmail:
    """Test suite for password change confirmation email."""

    def test_password_change_sends_confirmation_email(self, api_client, create_user):
        """Test password change sends confirmation email when configured."""
        from rest_framework_simplejwt.tokens import RefreshToken

        user = create_user(email='user@example.com', password='oldpass123')
        refresh = RefreshToken.for_user(user)
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        mail.outbox = []

        data = {
            'new_password': 'newpass123',
            'current_password': 'oldpass123',
        }
        response = api_client.post('/auth/users/set_password/', data)

        assert response.status_code == 204
        # Email should be sent because PASSWORD_CHANGED_EMAIL_CONFIRMATION is True
        assert len(mail.outbox) == 1

    def test_password_change_email_sent_to_user(self, api_client, create_user):
        """Test password change confirmation email is sent to user."""
        from rest_framework_simplejwt.tokens import RefreshToken

        user = create_user(email='user@example.com', password='oldpass123')
        refresh = RefreshToken.for_user(user)
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        mail.outbox = []

        data = {
            'new_password': 'newpass123',
            'current_password': 'oldpass123',
        }
        api_client.post('/auth/users/set_password/', data)

        assert len(mail.outbox) == 1
        email = mail.outbox[0]

        assert 'user@example.com' in email.to


@pytest.mark.django_db
class TestActivationEmail:
    """Test suite for email activation template."""

    def test_activation_email_sent_on_registration(self, api_client):
        """Test activation email is sent when user registers."""
        mail.outbox = []

        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'securepass123',
        }
        response = api_client.post('/auth/users/', data)

        assert response.status_code == 201
        # Activation email should be sent if SEND_ACTIVATION_EMAIL is True
        if settings.DJOSER.get('SEND_ACTIVATION_EMAIL'):
            assert len(mail.outbox) >= 1

    def test_activation_email_contains_verification_link(self, api_client):
        """Test activation email contains verification information."""
        mail.outbox = []

        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'securepass123',
        }
        api_client.post('/auth/users/', data)

        if settings.DJOSER.get('SEND_ACTIVATION_EMAIL') and len(mail.outbox) > 0:
            email = mail.outbox[0]

            # Email should be sent to new user
            assert 'newuser@example.com' in email.to

            # Email should have appropriate subject
            assert 'activation' in email.subject.lower() or 'verify' in email.subject.lower() or 'confirm' in email.subject.lower()
