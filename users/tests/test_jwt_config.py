"""
Tests for JWT configuration.

This module contains focused tests covering critical JWT settings and configuration.
"""

from datetime import timedelta
from django.conf import settings
from django.apps import apps


class TestJWTConfiguration:
    """Test suite for JWT configuration."""

    def test_simple_jwt_settings_are_loaded(self):
        """Test that SIMPLE_JWT settings dictionary is correctly loaded."""
        assert hasattr(settings, "SIMPLE_JWT")
        assert isinstance(settings.SIMPLE_JWT, dict)
        assert "ACCESS_TOKEN_LIFETIME" in settings.SIMPLE_JWT
        assert "REFRESH_TOKEN_LIFETIME" in settings.SIMPLE_JWT

    def test_access_token_lifetime_is_15_minutes(self):
        """Test that access token lifetime is configured to 15 minutes."""
        access_lifetime = settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"]
        assert access_lifetime == timedelta(minutes=15)

    def test_refresh_token_lifetime_is_7_days(self):
        """Test that refresh token lifetime is configured to 7 days."""
        refresh_lifetime = settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"]
        assert refresh_lifetime == timedelta(days=7)

    def test_token_blacklist_app_is_installed(self):
        """Test that token_blacklist app is installed and working."""
        assert "rest_framework_simplejwt.token_blacklist" in settings.INSTALLED_APPS
        assert apps.is_installed("rest_framework_simplejwt.token_blacklist")

    def test_jwt_authentication_in_default_classes(self):
        """Test that JWTAuthentication is in DEFAULT_AUTHENTICATION_CLASSES."""
        auth_classes = settings.REST_FRAMEWORK.get("DEFAULT_AUTHENTICATION_CLASSES", [])
        assert (
            "rest_framework_simplejwt.authentication.JWTAuthentication" in auth_classes
        )
