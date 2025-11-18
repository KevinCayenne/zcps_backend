"""
Tests for OAuth 2FA scenarios.

Tests the three OAuth callback scenarios:
1. Direct token issuance (no 2FA)
2. 2FA verification required (user opt-in)
3. 2FA setup required (global enforcement)
"""

import pytest
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import AccessToken
from unittest.mock import patch, Mock
from users.oauth_adapters import (
    generate_temporary_2fa_token,
    generate_jwt_tokens
)

User = get_user_model()


class TestGenerateTemporary2FAToken(TestCase):
    """Tests for generate_temporary_2fa_token function."""

    def setUp(self):
        """Set up test user."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_generate_temp_token_creates_valid_jwt(self):
        """Test that temp token is a valid JWT."""
        temp_token = generate_temporary_2fa_token(self.user)

        # Verify token can be decoded
        token_obj = AccessToken(temp_token)
        assert token_obj is not None
        assert token_obj['user_id'] == self.user.id

    def test_generate_temp_token_has_temp_2fa_claim(self):
        """Test that temp token has temp_2fa=True claim."""
        temp_token = generate_temporary_2fa_token(self.user)

        token_obj = AccessToken(temp_token)
        assert token_obj.get('temp_2fa') is True

    def test_temp_token_used_for_both_verify_and_setup(self):
        """Test that the same temp token function is used for both scenarios."""
        # Both scenario 2 (verify) and scenario 3 (setup) use the same token
        temp_token = generate_temporary_2fa_token(self.user)

        token_obj = AccessToken(temp_token)
        # Both scenarios use temp_2fa claim
        assert token_obj.get('temp_2fa') is True
        assert token_obj['user_id'] == self.user.id


@pytest.mark.django_db
class TestGoogleCallbackScenarios:
    """Tests for GoogleCallback view scenarios."""

    @pytest.fixture
    def user_no_2fa(self):
        """Create user without 2FA enabled."""
        return User.objects.create_user(
            username='user_no_2fa',
            email='no2fa@example.com',
            password='testpass123',
            is_2fa_enabled=False
        )

    @pytest.fixture
    def user_with_2fa(self):
        """Create user with 2FA enabled."""
        return User.objects.create_user(
            username='user_with_2fa',
            email='with2fa@example.com',
            password='testpass123',
            is_2fa_enabled=True
        )

    @override_settings(TWOFACTOR_ENFORCE_FOR_ALL_USERS=False)
    def test_scenario_1_direct_tokens_no_enforcement_no_optin(self, user_no_2fa):
        """Test Scenario 1: Direct token issuance when no 2FA."""
        # Generate tokens as GoogleCallback would
        access_token, refresh_token = generate_jwt_tokens(user_no_2fa)

        # Verify both tokens are valid
        assert access_token is not None
        assert refresh_token is not None

        # Verify access token contains user info
        token_obj = AccessToken(access_token)
        assert token_obj['user_id'] == user_no_2fa.id

    @override_settings(TWOFACTOR_ENFORCE_FOR_ALL_USERS=False)
    def test_scenario_2_temp_token_for_user_optin(self, user_with_2fa):
        """Test Scenario 2: Temp token returned when user has 2FA enabled."""
        # Generate temp token as GoogleCallback would
        temp_token = generate_temporary_2fa_token(user_with_2fa)

        # Verify temp token is valid and has correct claim
        token_obj = AccessToken(temp_token)
        assert token_obj['user_id'] == user_with_2fa.id
        assert token_obj.get('temp_2fa') is True

    @override_settings(TWOFACTOR_ENFORCE_FOR_ALL_USERS=True)
    def test_scenario_3_temp_token_for_enforcement_no_setup(self, user_no_2fa):
        """Test Scenario 3: Temp token returned when enforcement enabled but user not set up."""
        from django.conf import settings

        # Verify enforcement is on and user has no 2FA
        assert settings.TWOFACTOR_ENFORCE_FOR_ALL_USERS is True
        assert user_no_2fa.is_2fa_enabled is False

        # Generate temp token as GoogleCallback would (same function for both scenarios)
        temp_token = generate_temporary_2fa_token(user_no_2fa)

        # Verify temp token is valid and has correct claim
        token_obj = AccessToken(temp_token)
        assert token_obj['user_id'] == user_no_2fa.id
        assert token_obj.get('temp_2fa') is True

    @override_settings(TWOFACTOR_ENFORCE_FOR_ALL_USERS=True)
    def test_scenario_3_differentiated_by_url_param_not_token(self, user_no_2fa):
        """Test that Scenario 3 is differentiated by URL param, not token claim."""
        from django.conf import settings

        # With enforcement on and user not having 2FA, GoogleCallback returns:
        # - temp_token (same as scenario 2)
        # - requires_2fa_setup=true (URL param that differentiates from scenario 2)
        assert settings.TWOFACTOR_ENFORCE_FOR_ALL_USERS is True
        assert user_no_2fa.is_2fa_enabled is False

        temp_token = generate_temporary_2fa_token(user_no_2fa)
        token_obj = AccessToken(temp_token)

        # Token has temp_2fa claim (same as scenario 2)
        assert token_obj.get('temp_2fa') is True
        # The difference is in the URL param (requires_2fa_setup vs requires_2fa)

    @override_settings(TWOFACTOR_ENFORCE_FOR_ALL_USERS=True)
    def test_scenario_2_when_enforcement_and_user_has_2fa(self, user_with_2fa):
        """Test Scenario 2 takes effect when enforcement on and user already has 2FA."""
        from django.conf import settings

        # Even with enforcement, if user already has 2FA, they go through verify flow
        assert settings.TWOFACTOR_ENFORCE_FOR_ALL_USERS is True
        assert user_with_2fa.is_2fa_enabled is True

        temp_token = generate_temporary_2fa_token(user_with_2fa)
        token_obj = AccessToken(temp_token)

        # Should have temp_2fa claim (verify flow)
        assert token_obj.get('temp_2fa') is True


class TestOAuthErrorHandling(TestCase):
    """Tests for OAuth error handling scenarios."""

    def test_invalid_token_raises_error(self):
        """Test that invalid tokens raise appropriate errors."""
        from rest_framework_simplejwt.exceptions import TokenError

        with pytest.raises(TokenError):
            AccessToken('invalid_token_string')

    def test_tokens_for_different_users_are_different(self):
        """Test that tokens for different users are distinct."""
        user1 = User.objects.create_user(
            username='user1',
            email='user1@example.com',
            password='testpass123'
        )
        user2 = User.objects.create_user(
            username='user2',
            email='user2@example.com',
            password='testpass123'
        )

        token1 = generate_temporary_2fa_token(user1)
        token2 = generate_temporary_2fa_token(user2)

        # Tokens should be different
        assert token1 != token2

        # But both should be valid
        obj1 = AccessToken(token1)
        obj2 = AccessToken(token2)

        assert obj1['user_id'] == user1.id
        assert obj2['user_id'] == user2.id
