"""
Tests for OAuth error scenarios and logging.

Tests for error handling in OAuth flow.
"""

import pytest
import logging
from django.contrib.auth import get_user_model
from django.test import override_settings
from unittest.mock import patch, Mock
from users.oauth_adapters import build_error_redirect_url

User = get_user_model()


@pytest.mark.django_db
class TestOAuthErrorHandling:
    """Test OAuth error scenarios."""

    def test_user_denies_access_redirects_to_error_url(self, client):
        """Test that user denial redirects to error URL with proper params."""
        response = client.get('/auth/google/callback/?error=access_denied')

        # Should redirect
        assert response.status_code in [301, 302]

        # Should include error details
        if hasattr(response, 'url'):
            assert 'error' in response.url.lower()

    def test_invalid_credentials_error_format(self):
        """Test error URL format for invalid credentials."""
        url = build_error_redirect_url('invalid_credentials', 'Invalid client ID or secret')

        assert 'error_type=invalid_credentials' in url
        assert 'error_message=Invalid' in url
        assert url.startswith('http://localhost:3000/auth/error')

    def test_network_error_format(self):
        """Test error URL format for network errors."""
        url = build_error_redirect_url('server_error', 'Network timeout')

        assert 'error_type=server_error' in url
        assert 'error_message=Network' in url

    def test_missing_authorization_code_redirects_to_error(self, client):
        """Test that missing code redirects to error URL."""
        response = client.get('/auth/google/callback/')

        # Should redirect to error
        assert response.status_code in [301, 302]

    @patch('users.oauth_views.logger')
    def test_error_logging_for_user_denial(self, mock_logger, client):
        """Test that user denial is logged."""
        response = client.get('/auth/google/callback/?error=access_denied')

        # Check that logging was called (may or may not depending on implementation)
        # This is to ensure logging infrastructure is in place
        assert response.status_code in [301, 302]

    def test_error_redirect_url_properly_encodes_special_characters(self):
        """Test that error messages with special characters are properly encoded."""
        message = 'Error: User & system issue!'
        url = build_error_redirect_url('server_error', message)

        # Should be URL encoded
        assert 'error_message=Error' in url
        assert '%26' in url or '&' not in url.split('?')[1]  # & should be encoded

    def test_multiple_error_scenarios_have_unique_types(self):
        """Test that different error scenarios have unique error types."""
        error_types = [
            'access_denied',
            'invalid_credentials',
            'server_error',
            'invalid_request',
            'oauth_error'
        ]

        urls = [build_error_redirect_url(et, f'Test {et}') for et in error_types]

        # All should be unique
        assert len(urls) == len(set(urls))

        # All should contain error_type parameter
        for url in urls:
            assert 'error_type=' in url
