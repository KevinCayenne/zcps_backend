"""
Tests for two-factor authentication functionality.

Tests 2FA setup, login flow, verification, and admin enforcement.
"""

from datetime import timedelta
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.urls import reverse
from django.core import mail
from rest_framework.test import APIClient
from rest_framework import status
from unittest.mock import patch

from users.models import TwoFactorCode
from users.twofactor_utils import generate_2fa_code
from users.oauth_adapters import generate_temporary_2fa_token

User = get_user_model()


class TwoFactorSetupTests(TestCase):
    """Tests for 2FA setup flow."""

    def setUp(self):
        """Set up test client and user."""
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.client.force_authenticate(user=self.user)

    def test_enable_2fa_sends_code(self):
        """Test that enabling 2FA sends verification code."""
        response = self.client.post(reverse('2fa_enable'))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn('two-factor authentication code', mail.outbox[0].subject.lower())

    def test_enable_2fa_already_enabled(self):
        """Test enabling 2FA when already enabled returns error."""
        self.user.is_2fa_enabled = True
        self.user.save()

        response = self.client.post(reverse('2fa_enable'))

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('already enabled', response.data['error'].lower())

    def test_verify_setup_with_valid_code(self):
        """Test verifying 2FA setup with valid code."""
        # Generate code
        twofactor_code = generate_2fa_code(self.user)

        response = self.client.post(
            reverse('2fa_verify_setup'),
            {'code': twofactor_code.code}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_2fa_enabled)
        self.assertIsNotNone(self.user.twofa_setup_date)

    def test_verify_setup_with_invalid_code(self):
        """Test verifying 2FA setup with invalid code."""
        generate_2fa_code(self.user)

        response = self.client.post(
            reverse('2fa_verify_setup'),
            {'code': '999999'}
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_2fa_enabled)

    def test_disable_2fa_with_valid_password(self):
        """Test disabling 2FA with valid password."""
        self.user.is_2fa_enabled = True
        self.user.save()

        response = self.client.post(
            reverse('2fa_disable'),
            {'password': 'testpass123'}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_2fa_enabled)

    def test_disable_2fa_with_invalid_password(self):
        """Test disabling 2FA with invalid password."""
        self.user.is_2fa_enabled = True
        self.user.save()

        response = self.client.post(
            reverse('2fa_disable'),
            {'password': 'wrongpassword'}
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_2fa_enabled)

    def test_get_2fa_status(self):
        """Test retrieving 2FA status."""
        self.user.is_2fa_enabled = True
        self.user.twofa_setup_date = timezone.now()
        self.user.save()

        response = self.client.get(reverse('2fa_status'))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['is_2fa_enabled'])
        self.assertIsNotNone(response.data['twofa_setup_date'])


class TwoFactorLoginFlowTests(TestCase):
    """Tests for 2FA login flow."""

    def setUp(self):
        """Set up test client and user."""
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_login_without_2fa_returns_tokens(self):
        """Test login without 2FA enabled returns JWT tokens."""
        print(f"URL: {reverse('jwt-create')}")
        response = self.client.post(
            reverse('jwt-create'),
            {'email': 'test@example.com', 'password': 'testpass123'},
            format='json'
        )

        if response.status_code != status.HTTP_200_OK:
            print(f"Response status: {response.status_code}")
            print(f"Response data: {response.data}")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_login_with_2fa_returns_temp_token(self):
        """Test login with 2FA enabled returns temporary token."""
        self.user.is_2fa_enabled = True
        self.user.save()

        response = self.client.post(
            reverse('jwt-create'),
            {'email': 'test@example.com', 'password': 'testpass123'}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('temp_token', response.data)
        self.assertTrue(response.data['requires_2fa'])
        self.assertEqual(len(mail.outbox), 1)

    def test_verify_2fa_with_valid_code(self):
        """Test verifying 2FA during login with valid code."""
        self.user.is_2fa_enabled = True
        self.user.save()

        # Generate code
        twofactor_code = generate_2fa_code(self.user)
        temp_token = generate_temporary_2fa_token(self.user)

        # Verify code
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {temp_token}')
        response = self.client.post(
            reverse('2fa_verify_login'),
            {'code': twofactor_code.code}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

        # Check that last verification was updated
        self.user.refresh_from_db()
        self.assertIsNotNone(self.user.last_2fa_verification)

    def test_verify_2fa_with_invalid_code(self):
        """Test verifying 2FA during login with invalid code."""
        self.user.is_2fa_enabled = True
        self.user.save()

        generate_2fa_code(self.user)
        temp_token = generate_temporary_2fa_token(self.user)

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {temp_token}')
        response = self.client.post(
            reverse('2fa_verify_login'),
            {'code': '999999'}
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_verify_2fa_with_expired_code(self):
        """Test verifying 2FA with expired code."""
        self.user.is_2fa_enabled = True
        self.user.save()

        # Create expired code
        twofactor_code = TwoFactorCode.objects.create(
            user=self.user,
            code='123456',
            expires_at=timezone.now() - timedelta(minutes=1)
        )
        temp_token = generate_temporary_2fa_token(self.user)

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {temp_token}')
        response = self.client.post(
            reverse('2fa_verify_login'),
            {'code': '123456'}
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('expired', response.data['error'].lower())

    def test_resend_2fa_code(self):
        """Test resending 2FA code during login."""
        self.user.is_2fa_enabled = True
        self.user.save()

        temp_token = generate_temporary_2fa_token(self.user)

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {temp_token}')
        response = self.client.post(reverse('2fa_resend'))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertEqual(len(mail.outbox), 1)


class TwoFactorCodeModelTests(TestCase):
    """Tests for TwoFactorCode model."""

    def setUp(self):
        """Set up test user."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_code_is_valid_when_new(self):
        """Test that newly created code is valid."""
        code = generate_2fa_code(self.user)
        self.assertTrue(code.is_valid())

    def test_code_is_invalid_when_expired(self):
        """Test that expired code is invalid."""
        code = TwoFactorCode.objects.create(
            user=self.user,
            code='123456',
            expires_at=timezone.now() - timedelta(minutes=1)
        )
        self.assertFalse(code.is_valid())

    def test_code_is_invalid_when_used(self):
        """Test that used code is invalid."""
        code = generate_2fa_code(self.user)
        code.is_used = True
        code.save()
        self.assertFalse(code.is_valid())

    def test_code_is_invalid_after_max_attempts(self):
        """Test that code is invalid after max failed attempts."""
        code = generate_2fa_code(self.user)
        code.failed_attempts = 5
        code.save()
        self.assertFalse(code.is_valid(max_attempts=5))

    def test_generate_code_invalidates_previous(self):
        """Test that generating new code invalidates previous unused codes."""
        code1 = generate_2fa_code(self.user)
        code2 = generate_2fa_code(self.user)

        code1.refresh_from_db()
        self.assertTrue(code1.is_used)
        self.assertFalse(code2.is_used)


class TwoFactorUtilsTests(TestCase):
    """Tests for 2FA utility functions."""

    def setUp(self):
        """Set up test user."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_generate_2fa_code_creates_code(self):
        """Test that generate_2fa_code creates a valid code."""
        code = generate_2fa_code(self.user)

        self.assertEqual(len(code.code), 6)
        self.assertTrue(code.code.isdigit())
        self.assertGreater(code.expires_at, timezone.now())
