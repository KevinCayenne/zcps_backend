"""
Tests for User model OAuth fields.

Tests for google_id and profile_picture_url fields.
"""

import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError

User = get_user_model()


@pytest.mark.django_db
class TestUserOAuthFields:
    """Test User model OAuth fields."""

    def test_google_id_accepts_valid_id(self):
        """Test that google_id field accepts valid Google user IDs."""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            google_id='1234567890abcdef'
        )
        assert user.google_id == '1234567890abcdef'

    def test_google_id_uniqueness_constraint(self):
        """Test that google_id field has uniqueness constraint."""
        User.objects.create_user(
            username='testuser1',
            email='test1@example.com',
            password='testpass123',
            google_id='1234567890abcdef'
        )

        # Attempting to create another user with same google_id should raise IntegrityError
        with pytest.raises(IntegrityError):
            User.objects.create_user(
                username='testuser2',
                email='test2@example.com',
                password='testpass123',
                google_id='1234567890abcdef'
            )

    def test_profile_picture_url_accepts_valid_urls(self):
        """Test that profile_picture_url field accepts valid URLs."""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            profile_picture_url='https://example.com/profile.jpg'
        )
        assert user.profile_picture_url == 'https://example.com/profile.jpg'

    def test_oauth_fields_are_nullable_for_non_oauth_users(self):
        """Test that OAuth fields are nullable for non-OAuth users."""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        assert user.google_id is None
        assert user.profile_picture_url is None

    def test_user_creation_with_oauth_fields_populated(self):
        """Test User creation with OAuth fields populated."""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            google_id='1234567890abcdef',
            profile_picture_url='https://lh3.googleusercontent.com/a-/test'
        )
        assert user.google_id == '1234567890abcdef'
        assert user.profile_picture_url == 'https://lh3.googleusercontent.com/a-/test'
        assert user.email == 'test@example.com'

    def test_google_id_can_be_updated(self):
        """Test that google_id can be updated after user creation."""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        user.google_id = '1234567890abcdef'
        user.save()

        user.refresh_from_db()
        assert user.google_id == '1234567890abcdef'

    def test_profile_picture_url_can_be_long(self):
        """Test that profile_picture_url can handle long URLs."""
        long_url = 'https://lh3.googleusercontent.com/a-/ABC' + 'x' * 200
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            profile_picture_url=long_url
        )
        assert user.profile_picture_url == long_url
