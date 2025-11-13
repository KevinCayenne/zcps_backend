"""
Tests for OAuth endpoints and flow.

Tests for Google OAuth initiation, callback, and account linking.
"""

import pytest
from django.contrib.auth import get_user_model
from django.test import override_settings
from unittest.mock import patch, Mock
from users.oauth_adapters import (
    build_error_redirect_url,
    build_success_redirect_url,
    generate_jwt_tokens
)

User = get_user_model()


@pytest.mark.django_db
class TestOAuthEndpoints:
    """Test OAuth endpoints and flow."""

    def test_google_login_endpoint_exists(self, client):
        """Test that GET /auth/google/ endpoint exists."""
        # This endpoint should redirect to Google OAuth
        response = client.get('/auth/google/')
        # Should be redirect or method not allowed (POST required for dj-rest-auth)
        assert response.status_code in [301, 302, 405]

    def test_google_callback_endpoint_exists(self, client):
        """Test that GET /auth/google/callback/ endpoint exists."""
        # Without OAuth code, should redirect to error URL
        response = client.get('/auth/google/callback/')
        # Should redirect to error page or return error
        assert response.status_code in [301, 302, 400, 403]

    def test_build_error_redirect_url(self):
        """Test error redirect URL building."""
        url = build_error_redirect_url('access_denied', 'User denied access')
        assert 'error_type=access_denied' in url
        assert 'error_message=User+denied+access' in url
        assert url.startswith('http://localhost:3000/auth/error')

    def test_build_success_redirect_url(self):
        """Test success redirect URL building."""
        url = build_success_redirect_url('access_token_123', 'refresh_token_456')
        assert 'access=access_token_123' in url
        assert 'refresh=refresh_token_456' in url
        assert url.startswith('http://localhost:3000/auth/callback')

    def test_generate_jwt_tokens(self):
        """Test JWT token generation for OAuth users."""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

        access_token, refresh_token = generate_jwt_tokens(user)

        assert access_token is not None
        assert refresh_token is not None
        assert isinstance(access_token, str)
        assert isinstance(refresh_token, str)
        assert len(access_token) > 50
        assert len(refresh_token) > 50

    def test_oauth_callback_handles_user_denial(self, client):
        """Test that callback handles user denying OAuth access."""
        response = client.get('/auth/google/callback/?error=access_denied')

        # Should redirect to error URL
        assert response.status_code in [301, 302]
        assert 'error_type=access_denied' in response.url or 'error' in response.url

    def test_oauth_callback_missing_code(self, client):
        """Test that callback handles missing authorization code."""
        response = client.get('/auth/google/callback/')

        # Should redirect to error URL with invalid_request
        assert response.status_code in [301, 302]
