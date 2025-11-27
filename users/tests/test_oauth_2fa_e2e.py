"""
End-to-end integration tests for OAuth 2FA scenarios.

Tests complete workflows for all three OAuth scenarios
from callback through token generation.
"""

import pytest
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.core import mail
from rest_framework.test import APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import AccessToken

from users.oauth_adapters import (
    generate_temporary_2fa_token,
    generate_jwt_tokens
)
from users.twofactor_utils import generate_2fa_code

User = get_user_model()


class TestScenario1EndToEnd(TestCase):
    """End-to-end tests for Scenario 1: Direct token issuance."""

    def setUp(self):
        """Set up test user without 2FA."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            is_2fa_enabled=False
        )

    @override_settings(TWOFACTOR_ENFORCE_FOR_ALL_USERS=False)
    def test_complete_scenario_1_flow(self):
        """Test complete flow: OAuth -> direct tokens."""
        # Step 1: OAuth callback would generate tokens
        access_token, refresh_token = generate_jwt_tokens(self.user)

        # Step 2: Verify tokens are valid
        access_obj = AccessToken(access_token)
        assert access_obj['user_id'] == self.user.id

        # Step 3: Test that tokens can be used for authenticated requests
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')

        response = client.get(reverse('2fa_status'))
        assert response.status_code == status.HTTP_200_OK
        assert response.data['is_2fa_enabled'] is False


class TestScenario2EndToEnd(TestCase):
    """End-to-end tests for Scenario 2: 2FA verification required."""

    def setUp(self):
        """Set up test client and user with 2FA enabled."""
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            is_2fa_enabled=True
        )

    @override_settings(TWOFACTOR_ENFORCE_FOR_ALL_USERS=False)
    def test_complete_scenario_2_flow(self):
        """Test complete flow: OAuth -> temp token -> verify 2FA -> tokens."""
        # Step 1: OAuth callback would send code and return temp token
        twofactor_code = generate_2fa_code(self.user, verification_type='TWO_FACTOR')
        temp_token = generate_temporary_2fa_token(self.user)

        # Step 2: Verify temp token has correct claim
        temp_obj = AccessToken(temp_token)
        assert temp_obj.get('temp_2fa') is True

        # Step 3: Use temp token to verify 2FA code
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {temp_token}')
        response = self.client.post(
            reverse('2fa_verify_login'),
            {'code': twofactor_code.code}
        )

        # Step 4: Should receive full JWT tokens
        assert response.status_code == status.HTTP_200_OK
        assert 'access' in response.data
        assert 'refresh' in response.data

        # Step 5: Verify returned access token works
        new_access = response.data['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {new_access}')

        status_response = self.client.get(reverse('2fa_status'))
        assert status_response.status_code == status.HTTP_200_OK

    @override_settings(TWOFACTOR_ENFORCE_FOR_ALL_USERS=False)
    def test_scenario_2_with_invalid_code_fails(self):
        """Test that invalid code fails verification in Scenario 2."""
        generate_2fa_code(self.user, verification_type='TWO_FACTOR')
        temp_token = generate_temporary_2fa_token(self.user)

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {temp_token}')
        response = self.client.post(
            reverse('2fa_verify_login'),
            {'code': '999999'}  # Wrong code
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'error' in response.data


class TestScenario3EndToEnd(TestCase):
    """End-to-end tests for Scenario 3: 2FA setup required."""

    def setUp(self):
        """Set up test client and user without 2FA."""
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            is_2fa_enabled=False
        )

    @override_settings(TWOFACTOR_ENFORCE_FOR_ALL_USERS=True)
    def test_complete_scenario_3_flow(self):
        """Test complete flow: OAuth -> temp token -> enable 2FA -> verify -> tokens."""
        # Step 1: OAuth callback would return temp token (same as scenario 2)
        temp_token = generate_temporary_2fa_token(self.user)

        # Step 2: Verify temp token has correct claim
        temp_obj = AccessToken(temp_token)
        assert temp_obj.get('temp_2fa') is True
        assert temp_obj['user_id'] == self.user.id

        # Step 3: Use temp token to call enable endpoint
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {temp_token}')
        enable_response = self.client.post(
            reverse('2fa_enable'),
            {'method': 'email'}
        )

        assert enable_response.status_code == status.HTTP_200_OK
        assert 'expires_at' in enable_response.data
        assert len(mail.outbox) == 1  # Email was sent

        # Step 4: Get the code from the database (simulating email receipt)
        from users.models import TwoFactorCode
        twofactor_code = TwoFactorCode.objects.filter(
            user=self.user,
            is_used=False
        ).latest('created_at')

        # Step 5: Verify setup with the code
        verify_response = self.client.post(
            reverse('2fa_verify_setup'),
            {'code': twofactor_code.code}
        )

        assert verify_response.status_code == status.HTTP_200_OK

        # Step 6: Verify 2FA is now enabled
        self.user.refresh_from_db()
        assert self.user.is_2fa_enabled is True

    @override_settings(TWOFACTOR_ENFORCE_FOR_ALL_USERS=True)
    def test_scenario_3_temp_token_can_access_enable_endpoints(self):
        """Test that temp token can access 2FA enable endpoints."""
        # Temp token should work with enable endpoints (for setup flow)
        temp_token = generate_temporary_2fa_token(self.user)

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {temp_token}')
        response = self.client.post(
            reverse('2fa_enable'),
            {'method': 'email'}
        )

        # Should succeed since temp_2fa tokens can access enable endpoints
        assert response.status_code == status.HTTP_200_OK

    @override_settings(TWOFACTOR_ENFORCE_FOR_ALL_USERS=True)
    def test_scenario_3_user_already_has_2fa_enabled_error(self):
        """Test that enabling 2FA when already enabled returns error."""
        # Enable 2FA first
        self.user.is_2fa_enabled = True
        self.user.save()

        temp_token = generate_temporary_2fa_token(self.user)

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {temp_token}')
        response = self.client.post(
            reverse('2fa_enable'),
            {'method': 'email'}
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'already enabled' in response.data['error'].lower()


class TestOAuthTokenIntegration(TestCase):
    """Integration tests for OAuth token generation and validation."""

    def setUp(self):
        """Set up test users."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_temp_token_user_id_matches(self):
        """Test that temp token contains correct user ID."""
        temp_token = generate_temporary_2fa_token(self.user)
        token_obj = AccessToken(temp_token)

        assert token_obj['user_id'] == self.user.id

    def test_jwt_tokens_user_id_matches(self):
        """Test that JWT tokens contain correct user ID."""
        access_token, refresh_token = generate_jwt_tokens(self.user)
        token_obj = AccessToken(access_token)

        assert token_obj['user_id'] == self.user.id

    def test_temp_token_has_temp_2fa_claim(self):
        """Test that temp token has temp_2fa claim."""
        temp_token = generate_temporary_2fa_token(self.user)
        temp_obj = AccessToken(temp_token)

        # Temp token has temp_2fa claim
        assert temp_obj.get('temp_2fa') is True

    def test_jwt_token_does_not_have_temp_2fa_claim(self):
        """Test that full JWT token does not have temp_2fa claim."""
        access_token, _ = generate_jwt_tokens(self.user)
        access_obj = AccessToken(access_token)

        # Access token does not have temp_2fa
        assert access_obj.get('temp_2fa') is None


class TestStateTransitions(TestCase):
    """Tests for OAuth state transitions and edge cases."""

    def setUp(self):
        """Set up test client and user."""
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            is_2fa_enabled=False
        )

    def test_invalid_token_rejected(self):
        """Test that invalid token is rejected."""
        self.client.credentials(HTTP_AUTHORIZATION='Bearer invalid_token_string')
        response = self.client.post(
            reverse('2fa_verify_login'),
            {'code': '123456'}
        )

        # Should fail with 401 for invalid token
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_missing_token_rejected(self):
        """Test that missing token is rejected."""
        response = self.client.post(
            reverse('2fa_verify_login'),
            {'code': '123456'}
        )

        # Should fail with 401 for missing token
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @override_settings(TWOFACTOR_ENFORCE_FOR_ALL_USERS=True)
    def test_scenario_changes_when_user_enables_2fa(self):
        """Test that scenario changes when user enables 2FA during session."""
        # Initially user has no 2FA (would be Scenario 3 with enforcement)
        assert self.user.is_2fa_enabled is False

        # Generate tokens for initial state
        temp_token = generate_temporary_2fa_token(self.user)

        # User enables 2FA
        self.user.is_2fa_enabled = True
        self.user.save()

        # Now if they came back, they'd be Scenario 2
        # But the temp token was already issued, so it should still work
        # for the enable flow (they can complete setup)
        temp_obj = AccessToken(temp_token)
        assert temp_obj.get('temp_2fa') is True
