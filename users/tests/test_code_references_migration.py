"""
Tests for code references migration to settings-based config.

Tests that all code properly uses settings.TWOFACTOR_CONFIG instead of database.
"""

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.conf import settings

from users.twofactor_utils import generate_2fa_code

User = get_user_model()


class CodeReferencesMigrationTests(TestCase):
    """Tests for updated code references using settings."""

    def setUp(self):
        """Set up test user."""
        self.user = User.objects.create_user(
            username="testuser", email="test@example.com", password="testpass123"
        )

    def test_user_get_effective_2fa_method_uses_settings(self):
        """Test that User.get_effective_2fa_method() returns settings default."""
        # User without preferred method should return system default
        method = self.user.get_effective_2fa_method()
        self.assertEqual(method, settings.TWOFACTOR_CONFIG.default_2fa_method)
        self.assertEqual(method, "EMAIL")

    def test_user_get_effective_2fa_method_respects_user_preference(self):
        """Test that user preference overrides system default."""
        self.user.preferred_2fa_method = "PHONE"
        self.user.save()

        method = self.user.get_effective_2fa_method()
        self.assertEqual(method, "PHONE")

    def test_generate_2fa_code_uses_settings_expiration(self):
        """Test that generate_2fa_code() uses settings expiration time."""
        code = generate_2fa_code(self.user)

        # Calculate expected expiration
        expiration_seconds = settings.TWOFACTOR_CONFIG.code_expiration_seconds
        time_diff = (code.expires_at - code.created_at).total_seconds()

        # Allow 1 second tolerance for execution time
        self.assertAlmostEqual(time_diff, expiration_seconds, delta=1)

    def test_twofactor_code_is_valid_uses_max_attempts(self):
        """Test that TwoFactorCode.is_valid() respects max_attempts."""
        code = generate_2fa_code(self.user)

        # Code should be valid initially
        max_attempts = settings.TWOFACTOR_CONFIG.max_failed_attempts
        self.assertTrue(code.is_valid(max_attempts))

        # Set failed attempts to max
        code.failed_attempts = max_attempts
        code.save()

        # Code should now be invalid
        self.assertFalse(code.is_valid(max_attempts))
