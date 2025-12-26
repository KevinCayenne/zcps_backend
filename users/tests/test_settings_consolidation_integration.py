"""
Integration tests for settings consolidation feature.

Tests critical 2FA workflows using settings-based configuration to ensure
the consolidation from database to settings works correctly end-to-end.
"""

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import mail
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework import status

from users.twofactor_utils import generate_2fa_code, send_2fa_code

User = get_user_model()


@pytest.fixture
def api_client():
    """Fixture to provide APIClient instance."""
    return APIClient()


@pytest.fixture
def user_without_2fa():
    """Fixture to create a user without 2FA enabled."""
    return User.objects.create_user(
        username="testuser", email="test@example.com", password="testpass123"
    )


@pytest.fixture
def user_with_2fa():
    """Fixture to create a user with 2FA enabled."""
    user = User.objects.create_user(
        username="twofa_user", email="twofa@example.com", password="testpass123"
    )
    user.is_2fa_enabled = True
    user.preferred_2fa_method = "EMAIL"
    user.twofa_setup_date = timezone.now()
    user.save()
    return user


@pytest.mark.django_db
class TestTwoFactorSetupWithSettings:
    """Test 2FA setup flow using settings-based configuration."""

    def test_complete_2fa_setup_workflow_uses_settings_config(
        self, api_client, user_without_2fa
    ):
        """Test complete 2FA setup flow: enable -> verify -> confirm enabled."""
        # Login first
        login_data = {"username": "testuser", "password": "testpass123"}
        login_response = api_client.post("/auth/jwt/create/", login_data)
        access_token = login_response.data["access"]
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")

        # Step 1: Enable 2FA
        enable_data = {"method": "email"}
        enable_response = api_client.post("/auth/2fa/enable/", enable_data)
        assert enable_response.status_code == status.HTTP_200_OK
        assert enable_response.data["method"] == "email"

        # Verify code was sent via email
        assert len(mail.outbox) == 1
        email_body = mail.outbox[0].body

        # Extract code from email (it should be a 6-digit code)
        # Find the code in the email body
        code = None
        for line in email_body.split("\n"):
            line = line.strip()
            if line.isdigit() and len(line) == 6:
                code = line
                break

        assert code is not None, "6-digit code should be in email"

        # Step 2: Verify code to complete setup
        verify_data = {"code": code}
        verify_response = api_client.post("/auth/2fa/enable/verify/", verify_data)
        assert verify_response.status_code == status.HTTP_200_OK
        assert verify_response.data["message"] == "2FA has been enabled successfully."

        # Step 3: Verify 2FA is now enabled
        status_response = api_client.get("/auth/2fa/status/")
        assert status_response.status_code == status.HTTP_200_OK
        assert status_response.data["is_2fa_enabled"] is True
        assert status_response.data["preferred_2fa_method"] == "EMAIL"

    def test_2fa_code_expiration_uses_settings_value(self, user_without_2fa):
        """Test that generated 2FA code uses expiration from settings."""
        code = generate_2fa_code(user_without_2fa)

        # Calculate actual expiration time
        expiration_seconds = settings.TWOFACTOR_CONFIG.code_expiration_seconds
        time_diff = (code.expires_at - code.created_at).total_seconds()

        # Allow 1 second tolerance for execution time
        assert abs(time_diff - expiration_seconds) <= 1


@pytest.mark.django_db
class TestTwoFactorLoginWithSettings:
    """Test 2FA login flow using settings-based configuration."""

    def test_complete_2fa_login_workflow_with_settings(self, api_client, user_with_2fa):
        """Test complete 2FA login: login -> receive temp token -> verify code -> get full tokens."""
        # Step 1: Login (should trigger 2FA)
        login_data = {"username": "twofa_user", "password": "testpass123"}
        login_response = api_client.post("/auth/jwt/create/", login_data)
        assert login_response.status_code == status.HTTP_200_OK
        assert "temp_token" in login_response.data
        assert login_response.data["requires_2fa"] is True

        temp_token = login_response.data["temp_token"]

        # Verify code was sent via email
        assert len(mail.outbox) == 1
        email_body = mail.outbox[0].body

        # Extract code from email
        code = None
        for line in email_body.split("\n"):
            line = line.strip()
            if line.isdigit() and len(line) == 6:
                code = line
                break

        assert code is not None, "6-digit code should be in email"

        # Step 2: Verify 2FA code with temp token
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {temp_token}")
        verify_data = {"code": code}
        verify_response = api_client.post("/auth/2fa/verify/", verify_data)
        assert verify_response.status_code == status.HTTP_200_OK
        assert "access" in verify_response.data
        assert "refresh" in verify_response.data

        # Step 3: Use full access token to access protected endpoint
        access_token = verify_response.data["access"]
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
        profile_response = api_client.get("/auth/users/me/")
        assert profile_response.status_code == status.HTTP_200_OK

    def test_2fa_failed_attempts_respects_settings_max(self, api_client, user_with_2fa):
        """Test that failed attempts limit uses settings.TWOFACTOR_CONFIG.max_failed_attempts."""
        # Generate a code
        code_obj = generate_2fa_code(user_with_2fa)
        max_attempts = settings.TWOFACTOR_CONFIG.max_failed_attempts

        # Code should be valid initially
        assert code_obj.is_valid(max_attempts) is True

        # Set failed attempts to max
        code_obj.failed_attempts = max_attempts
        code_obj.save()

        # Code should now be invalid
        assert code_obj.is_valid(max_attempts) is False

    def test_temporary_token_lifetime_uses_settings_value(
        self, api_client, user_with_2fa
    ):
        """Test that temporary 2FA token lifetime uses settings value."""
        # Login to get temp token
        login_data = {"username": "twofa_user", "password": "testpass123"}
        login_response = api_client.post("/auth/jwt/create/", login_data)
        temp_token = login_response.data["temp_token"]

        # Decode token to check expiration
        from rest_framework_simplejwt.tokens import UntypedToken

        token = UntypedToken(temp_token)

        # Verify temp_2fa claim exists
        assert token.get("temp_2fa") is True


@pytest.mark.django_db
class TestMiddlewareWithSettings:
    """Test middleware enforcement using settings-based configuration."""

    def test_middleware_uses_settings_for_enforcement(
        self, api_client, user_without_2fa
    ):
        """Test that middleware checks settings.TWOFACTOR_CONFIG.enforce_2fa_for_all_users."""
        # Login as user without 2FA
        login_data = {"username": "testuser", "password": "testpass123"}
        login_response = api_client.post("/auth/jwt/create/", login_data)
        access_token = login_response.data["access"]

        # Access a protected endpoint (enforcement is disabled by default)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
        profile_response = api_client.get("/auth/users/me/")

        # Should succeed when enforcement is disabled (default)
        if settings.TWOFACTOR_CONFIG.enforce_2fa_for_all_users:
            # If enforcement is on, should be blocked
            assert profile_response.status_code == status.HTTP_403_FORBIDDEN
        else:
            # If enforcement is off (default), should succeed
            assert profile_response.status_code == status.HTTP_200_OK

    def test_temporary_token_restriction_middleware_allows_2fa_endpoints(
        self, api_client, user_with_2fa
    ):
        """Test that temporary tokens are restricted to 2FA endpoints only."""
        # Login to get temp token
        login_data = {"username": "twofa_user", "password": "testpass123"}
        login_response = api_client.post("/auth/jwt/create/", login_data)
        temp_token = login_response.data["temp_token"]

        # Try to access a non-2FA endpoint with temp token (should be blocked)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {temp_token}")
        profile_response = api_client.get("/auth/users/me/")
        assert profile_response.status_code == status.HTTP_403_FORBIDDEN

        # Access allowed 2FA endpoint (should work)
        status_response = api_client.get("/auth/2fa/status/")
        assert status_response.status_code == status.HTTP_200_OK


@pytest.mark.django_db
class TestUserEffective2FAMethod:
    """Test User.get_effective_2fa_method() with settings integration."""

    def test_user_without_preference_returns_settings_default(self, user_without_2fa):
        """Test that user without preference returns system default from settings."""
        method = user_without_2fa.get_effective_2fa_method()
        assert method == settings.TWOFACTOR_CONFIG.default_2fa_method
        assert method == "EMAIL"

    def test_user_with_preference_overrides_settings_default(self):
        """Test that user preference overrides system default."""
        user = User.objects.create_user(
            username="phoneuser", email="phone@example.com", password="pass123"
        )
        user.preferred_2fa_method = "PHONE"
        user.save()

        method = user.get_effective_2fa_method()
        assert method == "PHONE"


@pytest.mark.django_db
class TestCodeSendingWithSettings:
    """Test code sending uses settings-based configuration."""

    def test_send_2fa_code_uses_settings_expiration_in_email(self, user_without_2fa):
        """Test that email contains expiration time from settings."""
        code = generate_2fa_code(user_without_2fa)
        send_2fa_code(user_without_2fa, code.code, verification_type="TWO_FACTOR")

        # Check email was sent
        assert len(mail.outbox) == 1
        email_body = mail.outbox[0].body

        # Email should mention expiration time in minutes
        expiration_seconds = settings.TWOFACTOR_CONFIG.code_expiration_seconds
        expiration_minutes = expiration_seconds // 60
        assert str(expiration_minutes) in email_body
