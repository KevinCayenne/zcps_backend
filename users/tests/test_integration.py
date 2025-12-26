"""
Integration tests for authentication workflows.

This module contains end-to-end tests covering complete user journeys.
"""

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status

User = get_user_model()


@pytest.fixture
def api_client():
    """Fixture to provide APIClient instance."""
    return APIClient()


@pytest.mark.django_db
class TestCompleteAuthenticationWorkflow:
    """Test suite for end-to-end authentication workflows."""

    def test_complete_registration_login_profile_update_logout_workflow(
        self, api_client
    ):
        """Test registration → login → profile retrieval → profile update → logout workflow."""
        # Note: SEND_ACTIVATION_EMAIL is disabled in testing settings

        # Step 1: Register a new user
        register_data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "securepass123",
            "first_name": "New",
            "last_name": "User",
            "phone_number": "+1 234 5678901",
        }
        register_response = api_client.post("/auth/users/", register_data)
        assert register_response.status_code == status.HTTP_201_CREATED
        assert register_response.data["username"] == "newuser"

        # Step 2: Login with the new user
        login_data = {
            "username": "newuser",
            "password": "securepass123",
        }
        login_response = api_client.post("/auth/jwt/create/", login_data)
        assert login_response.status_code == status.HTTP_200_OK
        access_token = login_response.data["access"]
        refresh_token = login_response.data["refresh"]

        # Step 3: Retrieve profile
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
        profile_response = api_client.get("/auth/users/me/")
        assert profile_response.status_code == status.HTTP_200_OK
        assert profile_response.data["email"] == "newuser@example.com"
        assert profile_response.data["first_name"] == "New"

        # Step 4: Update profile
        update_data = {
            "first_name": "Updated",
            "last_name": "Name",
            "phone_number": "+44 20 1234 5678",
        }
        update_response = api_client.patch("/auth/users/me/", update_data)
        assert update_response.status_code == status.HTTP_200_OK
        assert update_response.data["first_name"] == "Updated"
        assert update_response.data["phone_number"] == "+44 20 1234 5678"

        # Step 5: Logout
        logout_data = {"refresh": refresh_token}
        logout_response = api_client.post("/auth/logout/", logout_data)
        assert logout_response.status_code == status.HTTP_204_NO_CONTENT

        # Step 6: Verify refresh token is blacklisted
        refresh_response = api_client.post("/auth/jwt/refresh/", logout_data)
        assert refresh_response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_login_access_protected_endpoint_token_refresh_workflow(self, api_client):
        """Test login → access protected endpoint → token expires → refresh token → access again workflow."""
        # Create a user
        User.objects.create_user(
            username="testuser", email="test@example.com", password="testpass123"
        )

        # Step 1: Login
        login_data = {"username": "testuser", "password": "testpass123"}
        login_response = api_client.post("/auth/jwt/create/", login_data)
        assert login_response.status_code == status.HTTP_200_OK
        access_token = login_response.data["access"]
        refresh_token = login_response.data["refresh"]

        # Step 2: Access protected endpoint
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
        profile_response = api_client.get("/auth/users/me/")
        assert profile_response.status_code == status.HTTP_200_OK

        # Step 3: Refresh the access token
        refresh_data = {"refresh": refresh_token}
        refresh_response = api_client.post("/auth/jwt/refresh/", refresh_data)
        assert refresh_response.status_code == status.HTTP_200_OK
        new_access_token = refresh_response.data["access"]

        # Step 4: Access protected endpoint with new token
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {new_access_token}")
        profile_response2 = api_client.get("/auth/users/me/")
        assert profile_response2.status_code == status.HTTP_200_OK

    def test_registration_with_invalid_email_format_returns_validation_error(
        self, api_client
    ):
        """Test registration with invalid email format returns validation error."""
        register_data = {
            "username": "testuser",
            "email": "invalid-email",
            "password": "securepass123",
        }
        response = api_client.post("/auth/users/", register_data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "email" in response.data

    def test_profile_update_with_duplicate_email_returns_validation_error(
        self, api_client
    ):
        """Test profile update with duplicate email returns validation error."""
        # Create two users
        User.objects.create_user(
            username="user1", email="user1@example.com", password="pass123"
        )
        User.objects.create_user(
            username="user2", email="user2@example.com", password="pass123"
        )

        # Login as user2
        login_data = {"username": "user2", "password": "pass123"}
        login_response = api_client.post("/auth/jwt/create/", login_data)
        access_token = login_response.data["access"]

        # Try to update user2's email to user1's email
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
        update_data = {"email": "user1@example.com"}
        update_response = api_client.patch("/auth/users/me/", update_data)
        assert update_response.status_code == status.HTTP_400_BAD_REQUEST
        assert "email" in update_response.data

    def test_account_deletion_removes_user_from_database(self, api_client):
        """Test account deletion removes user from database."""
        # Create a user
        user = User.objects.create_user(
            username="deleteuser", email="delete@example.com", password="pass123"
        )
        user_id = user.id

        # Login
        login_data = {"username": "deleteuser", "password": "pass123"}
        login_response = api_client.post("/auth/jwt/create/", login_data)
        access_token = login_response.data["access"]

        # Delete account
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
        # Provide current password for Djoser's delete view
        delete_data = {"current_password": "pass123"}
        delete_response = api_client.delete("/auth/users/me/", delete_data)
        assert delete_response.status_code == status.HTTP_204_NO_CONTENT

        # Verify user is deleted
        assert not User.objects.filter(id=user_id).exists()

    def test_token_verification_endpoint_with_valid_and_invalid_tokens(
        self, api_client
    ):
        """Test token verification endpoint with valid and invalid tokens."""
        # Create a user and get tokens
        User.objects.create_user(
            username="testuser", email="test@example.com", password="pass123"
        )
        login_data = {"username": "testuser", "password": "pass123"}
        login_response = api_client.post("/auth/jwt/create/", login_data)
        access_token = login_response.data["access"]

        # Verify valid token
        verify_data = {"token": access_token}
        verify_response = api_client.post("/auth/jwt/verify/", verify_data)
        assert verify_response.status_code == status.HTTP_200_OK

        # Verify invalid token
        invalid_verify_data = {"token": "invalid-token-12345"}
        invalid_verify_response = api_client.post(
            "/auth/jwt/verify/", invalid_verify_data
        )
        assert invalid_verify_response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_dual_identifier_login_same_user_can_login_with_email_or_username(
        self, api_client
    ):
        """Test dual identifier login (same user can log in with email or username)."""
        # Create a user
        User.objects.create_user(
            username="dualuser", email="dual@example.com", password="pass123"
        )

        # Login with username
        username_login_data = {"username": "dualuser", "password": "pass123"}
        username_login_response = api_client.post(
            "/auth/jwt/create/", username_login_data
        )
        assert username_login_response.status_code == status.HTTP_200_OK
        assert "access" in username_login_response.data

        # Login with email (using username field but email value)
        email_login_data = {"username": "dual@example.com", "password": "pass123"}
        email_login_response = api_client.post("/auth/jwt/create/", email_login_data)
        assert email_login_response.status_code == status.HTTP_200_OK
        assert "access" in email_login_response.data

    def test_registration_with_weak_password_returns_validation_error(self, api_client):
        """Test registration with weak password returns Django's password validator errors."""
        register_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "123",  # Too short
        }
        response = api_client.post("/auth/users/", register_data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "password" in response.data

    def test_unauthenticated_access_to_protected_endpoint_returns_401(self, api_client):
        """Test that accessing protected endpoint without token returns 401."""
        response = api_client.get("/auth/users/me/")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
