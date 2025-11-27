"""
Tests for settings consolidation - TwoFactorConfig dataclass.

Tests the new settings-based 2FA configuration.
"""

from django.test import TestCase, override_settings
from django.conf import settings
from dataclasses import FrozenInstanceError


class TwoFactorConfigDataclassTests(TestCase):
    """Tests for TwoFactorConfig dataclass."""

    def test_twofactor_config_exists(self):
        """Test that TWOFACTOR_CONFIG exists in settings."""
        self.assertTrue(hasattr(settings, 'TWOFACTOR_CONFIG'))
        self.assertIsNotNone(settings.TWOFACTOR_CONFIG)

    def test_twofactor_config_default_values(self):
        """Test that TwoFactorConfig has correct default values."""
        config = settings.TWOFACTOR_CONFIG

        self.assertEqual(config.enforce_2fa_for_all_users, False)
        self.assertEqual(config.default_2fa_method, 'EMAIL')
        self.assertEqual(config.code_expiration_seconds, 600)
        self.assertEqual(config.max_failed_attempts, 5)
        self.assertEqual(config.temporary_token_lifetime_minutes, 10)

    def test_twofactor_config_field_types(self):
        """Test that TwoFactorConfig fields have correct types."""
        config = settings.TWOFACTOR_CONFIG

        self.assertIsInstance(config.enforce_2fa_for_all_users, bool)
        self.assertIsInstance(config.default_2fa_method, str)
        self.assertIsInstance(config.code_expiration_seconds, int)
        self.assertIsInstance(config.max_failed_attempts, int)
        self.assertIsInstance(config.temporary_token_lifetime_minutes, int)

    def test_twofactor_config_is_frozen(self):
        """Test that TwoFactorConfig is immutable (frozen)."""
        config = settings.TWOFACTOR_CONFIG

        # Attempt to modify should raise FrozenInstanceError
        with self.assertRaises(FrozenInstanceError):
            config.enforce_2fa_for_all_users = True

    def test_twofactor_config_attribute_access(self):
        """Test direct attribute access pattern works."""
        # Test that we can access attributes directly without errors
        config = settings.TWOFACTOR_CONFIG

        # These should all work without errors
        _ = config.enforce_2fa_for_all_users
        _ = config.default_2fa_method
        _ = config.code_expiration_seconds
        _ = config.max_failed_attempts
        _ = config.temporary_token_lifetime_minutes

        # Verify we can use them in expressions
        self.assertTrue(config.code_expiration_seconds > 0)
        self.assertTrue(config.max_failed_attempts > 0)
