"""
Tests for API endpoints.

This module contains focused tests covering critical authentication endpoints.
"""

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

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
            "username": "testuser",
            "email": "test@example.com",
            "password": "testpass123",
        }
        defaults.update(kwargs)
        password = defaults.pop("password")
        user = User.objects.create_user(**defaults)
        user.set_password(password)
        user.save()
        return user

    return make_user


@pytest.mark.django_db
class TestUserRegistrationEndpoint:
    """Test suite for user registration endpoint."""

    def test_registration_with_valid_data_returns_201(self, api_client):
        """Test POST /auth/users/ registration with valid data returns 201."""
        data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "securepass123",
            "phone_number": "+1 234 5678901",
        }
        response = api_client.post("/auth/users/", data)
        assert response.status_code == status.HTTP_201_CREATED
        assert "password" not in response.data
        assert response.data["email"] == "newuser@example.com"
        assert response.data["username"] == "newuser"

    def test_registration_with_duplicate_email_returns_400(
        self, api_client, create_user
    ):
        """Test POST /auth/users/ with duplicate email returns 400."""
        create_user(email="existing@example.com", username="existing")
        data = {
            "username": "newuser",
            "email": "existing@example.com",
            "password": "securepass123",
        }
        response = api_client.post("/auth/users/", data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "email" in response.data


@pytest.mark.django_db
class TestLoginEndpoint:
    """Test suite for login endpoint."""

    def test_login_with_email_returns_tokens(self, api_client, create_user):
        """Test POST /auth/jwt/create/ login with email returns tokens."""
        create_user(
            email="user@example.com", username="testuser", password="testpass123"
        )
        # SimpleJWT expects 'username' field, but our custom backend accepts email as username value
        data = {
            "username": "user@example.com",  # Field name is 'username' but value is email
            "password": "testpass123",
        }
        response = api_client.post("/auth/jwt/create/", data)
        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data
        assert "refresh" in response.data

    def test_login_with_username_returns_tokens(self, api_client, create_user):
        """Test POST /auth/jwt/create/ login with username returns tokens."""
        create_user(
            email="user@example.com", username="testuser", password="testpass123"
        )
        # Field name is 'username' and value is username
        data = {
            "username": "testuser",
            "password": "testpass123",
        }
        response = api_client.post("/auth/jwt/create/", data)
        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data
        assert "refresh" in response.data

    def test_login_with_invalid_credentials_returns_401(self, api_client, create_user):
        """Test POST /auth/jwt/create/ with invalid credentials returns 401."""
        create_user(
            email="user@example.com", username="testuser", password="testpass123"
        )
        data = {
            "username": "user@example.com",
            "password": "wrongpassword",
        }
        response = api_client.post("/auth/jwt/create/", data)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
class TestProfileEndpoint:
    """Test suite for profile retrieval endpoint."""

    def test_profile_retrieval_with_valid_token_returns_user_data(
        self, api_client, create_user
    ):
        """Test GET /auth/users/me/ with valid token returns user data."""
        user = create_user(email="user@example.com", username="testuser")
        refresh = RefreshToken.for_user(user)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")

        response = api_client.get("/auth/users/me/")
        assert response.status_code == status.HTTP_200_OK
        assert response.data["email"] == "user@example.com"
        assert response.data["username"] == "testuser"
        assert "password" not in response.data


@pytest.mark.django_db
class TestTokenRefreshEndpoint:
    """Test suite for token refresh endpoint."""

    def test_token_refresh_with_valid_refresh_token_returns_new_access_token(
        self, api_client, create_user
    ):
        """Test POST /auth/jwt/refresh/ with valid refresh token returns new access token."""
        user = create_user()
        refresh = RefreshToken.for_user(user)
        data = {"refresh": str(refresh)}

        response = api_client.post("/auth/jwt/refresh/", data)
        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data


@pytest.mark.django_db
class TestLogoutEndpoint:
    """Test suite for custom logout endpoint."""

    def test_logout_blacklists_refresh_token(self, api_client, create_user):
        """Test custom POST /auth/logout/ blacklists refresh token."""
        user = create_user()
        refresh = RefreshToken.for_user(user)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")

        data = {"refresh": str(refresh)}
        response = api_client.post("/auth/logout/", data)
        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Try to refresh with the blacklisted token
        refresh_response = api_client.post("/auth/jwt/refresh/", data)
        assert refresh_response.status_code == status.HTTP_401_UNAUTHORIZED
