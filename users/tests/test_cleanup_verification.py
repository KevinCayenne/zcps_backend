"""
Tests for database model and dependency cleanup verification.

Tests that TwoFactorSettings model and django-solo have been removed.
"""

from django.test import TestCase
from django.conf import settings


class CleanupVerificationTests(TestCase):
    """Tests for removal verification."""

    def test_twofactorsettings_model_not_exists(self):
        """Test that TwoFactorSettings model no longer exists."""
        # Attempting to import should fail
        with self.assertRaises(ImportError):
            from users.models import TwoFactorSettings

    def test_django_solo_not_in_installed_apps(self):
        """Test that django-solo is not in INSTALLED_APPS."""
        self.assertNotIn('solo', settings.INSTALLED_APPS)

    def test_admin_does_not_include_twofactorsettings(self):
        """Test that admin does not try to register TwoFactorSettings."""
        from users import admin as users_admin

        # Check that TwoFactorSettings is not imported
        self.assertFalse(hasattr(users_admin, 'TwoFactorSettings'))
        self.assertFalse(hasattr(users_admin, 'TwoFactorSettingsAdmin'))

    def test_migration_exists(self):
        """Test that migration to remove TwoFactorSettings exists."""
        import os
        migration_path = '/Users/ofang/Documents/Github/django_boilerplate/users/migrations/0008_remove_twofactorsettings.py'
        self.assertTrue(os.path.exists(migration_path),
                       "Migration 0008_remove_twofactorsettings.py should exist")

    def test_settings_uses_dataclass(self):
        """Test that settings now uses TwoFactorConfig dataclass."""
        self.assertTrue(hasattr(settings, 'TWOFACTOR_CONFIG'))

        # Verify it's a dataclass
        from dataclasses import is_dataclass
        self.assertTrue(is_dataclass(settings.TWOFACTOR_CONFIG))
