"""
Tests for User model.

This module contains focused tests covering critical behaviors of the custom User model.
"""

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError

User = get_user_model()


@pytest.mark.django_db
class TestUserModel:
    """Test suite for User model."""

    def test_phone_number_accepts_valid_international_format(self):
        """Test that phone_number field accepts valid international format (+XXX XXXXXXXXXX)."""
        user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123",
            phone_number="+1 234 5678901",
        )
        assert user.phone_number == "+1 234 5678901"

    def test_phone_number_accepts_null_values(self):
        """Test that phone_number field accepts null and blank values."""
        user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123",
            phone_number=None,
        )
        assert user.phone_number is None

    def test_phone_number_accepts_blank_values(self):
        """Test that phone_number field accepts blank string."""
        user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123",
            phone_number="",
        )
        assert user.phone_number == ""

    def test_email_field_is_required(self):
        """Test that email field is required (blank=False validation)."""
        user = User(username="testuser", email="", password="testpass123")
        with pytest.raises(ValidationError) as exc_info:
            user.full_clean()
        assert "email" in exc_info.value.error_dict

    def test_created_at_and_updated_at_timestamps_auto_populated(self):
        """Test that created_at and updated_at timestamps are auto-populated."""
        user = User.objects.create_user(
            username="testuser", email="test@example.com", password="testpass123"
        )
        assert user.created_at is not None
        assert user.updated_at is not None

    def test_user_creation_with_all_fields(self):
        """Test user creation with all fields (username, email, phone_number)."""
        user = User.objects.create_user(
            username="johndoe",
            email="john@example.com",
            password="securepass123",
            phone_number="+44 20 1234 5678",
            first_name="John",
            last_name="Doe",
        )
        assert user.username == "johndoe"
        assert user.email == "john@example.com"
        assert user.phone_number == "+44 20 1234 5678"
        assert user.first_name == "John"
        assert user.last_name == "Doe"
        assert user.check_password("securepass123")

    def test_username_uniqueness_constraint(self):
        """Test that username uniqueness constraint is enforced."""
        User.objects.create_user(
            username="testuser", email="test1@example.com", password="testpass123"
        )
        with pytest.raises(IntegrityError):
            User.objects.create_user(
                username="testuser", email="test2@example.com", password="testpass123"
            )

    def test_email_uniqueness_validation(self):
        """Test that email uniqueness is enforced."""
        User.objects.create_user(
            username="testuser1", email="test@example.com", password="testpass123"
        )
        with pytest.raises(IntegrityError):
            User.objects.create_user(
                username="testuser2", email="test@example.com", password="testpass123"
            )
