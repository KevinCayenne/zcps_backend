"""
Tests for password management configuration settings.

This module tests that password management settings are correctly loaded
from environment variables and have appropriate defaults.
"""

import pytest
from django.conf import settings


@pytest.mark.django_db
class TestPasswordManagementConfiguration:
    """Test suite for password management configuration settings."""

    def test_password_reset_timeout_is_configured(self):
        """Test PASSWORD_RESET_TIMEOUT is configured with correct default."""
        # Should default to 86400 seconds (24 hours)
        assert hasattr(settings, 'PASSWORD_RESET_TIMEOUT')
        assert isinstance(settings.PASSWORD_RESET_TIMEOUT, int)
        assert settings.PASSWORD_RESET_TIMEOUT > 0

    def test_frontend_url_is_configured(self):
        """Test FRONTEND_URL is configured for email links."""
        assert hasattr(settings, 'FRONTEND_URL')
        assert isinstance(settings.FRONTEND_URL, str)
        assert settings.FRONTEND_URL != ''

    def test_blacklist_tokens_on_password_change_is_boolean(self):
        """Test BLACKLIST_TOKENS_ON_PASSWORD_CHANGE is a boolean setting."""
        assert hasattr(settings, 'BLACKLIST_TOKENS_ON_PASSWORD_CHANGE')
        assert isinstance(settings.BLACKLIST_TOKENS_ON_PASSWORD_CHANGE, bool)

    def test_djoser_password_changed_email_confirmation_enabled(self):
        """Test Djoser PASSWORD_CHANGED_EMAIL_CONFIRMATION is enabled."""
        assert hasattr(settings, 'DJOSER')
        assert 'PASSWORD_CHANGED_EMAIL_CONFIRMATION' in settings.DJOSER
        assert settings.DJOSER['PASSWORD_CHANGED_EMAIL_CONFIRMATION'] is True

    def test_djoser_activation_url_configured(self):
        """Test Djoser ACTIVATION_URL is properly configured."""
        assert 'ACTIVATION_URL' in settings.DJOSER
        assert isinstance(settings.DJOSER['ACTIVATION_URL'], str)

    def test_djoser_password_reset_confirm_url_configured(self):
        """Test Djoser PASSWORD_RESET_CONFIRM_URL is properly configured."""
        assert 'PASSWORD_RESET_CONFIRM_URL' in settings.DJOSER
        assert isinstance(settings.DJOSER['PASSWORD_RESET_CONFIRM_URL'], str)
