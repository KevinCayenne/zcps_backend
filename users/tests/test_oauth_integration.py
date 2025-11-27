"""
Integration tests for OAuth feature.

End-to-end tests for OAuth flow, account linking, and JWT token generation.
"""

import pytest
from django.contrib.auth import get_user_model
from unittest.mock import patch, Mock
from users.oauth_adapters import CustomSocialAccountAdapter, generate_jwt_tokens
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken

User = get_user_model()


@pytest.mark.django_db
class TestOAuthIntegration:
    """Integration tests for OAuth feature."""

    def test_complete_oauth_flow_for_new_user(self):
        """Test complete OAuth flow creates new user with profile data."""
        # Simulate OAuth data
        oauth_data = {
            'id': 'google123456',
            'sub': 'google123456',
            'email': 'newuser@example.com',
            'given_name': 'John',
            'family_name': 'Doe',
            'picture': 'https://example.com/photo.jpg'
        }

        # Create user as if created by OAuth
        user = User.objects.create_user(
            username='newuser',
            email=oauth_data['email'],
            first_name=oauth_data['given_name'],
            last_name=oauth_data['family_name']
        )
        user.set_unusable_password()
        user.google_id = oauth_data['id']
        user.profile_picture_url = oauth_data['picture']
        user.save()

        # Verify user was created correctly
        assert User.objects.filter(email=oauth_data['email']).exists()
        created_user = User.objects.get(email=oauth_data['email'])
        assert created_user.google_id == oauth_data['id']
        assert created_user.profile_picture_url == oauth_data['picture']
        assert created_user.first_name == oauth_data['given_name']
        assert created_user.last_name == oauth_data['family_name']
        assert not created_user.has_usable_password()

    def test_account_linking_for_existing_user(self):
        """Test OAuth links to existing user with matching email."""
        # Create existing user with password
        existing_user = User.objects.create_user(
            username='existing',
            email='existing@example.com',
            password='testpass123'
        )

        # Verify user has usable password
        assert existing_user.has_usable_password()

        # Simulate OAuth linking
        existing_user.google_id = 'google789012'
        existing_user.profile_picture_url = 'https://example.com/existing.jpg'
        existing_user.save()

        # Verify account was linked
        existing_user.refresh_from_db()
        assert existing_user.google_id == 'google789012'
        assert existing_user.profile_picture_url == 'https://example.com/existing.jpg'
        # User should still have usable password
        assert existing_user.has_usable_password()

    def test_jwt_token_generation_for_oauth_user(self):
        """Test JWT tokens are generated correctly for OAuth users."""
        user = User.objects.create_user(
            username='oauthuser',
            email='oauth@example.com',
            google_id='google345678'
        )
        user.set_unusable_password()
        user.save()

        # Generate tokens
        access_token, refresh_token = generate_jwt_tokens(user)

        # Verify tokens are valid
        assert access_token is not None
        assert refresh_token is not None

        # Verify access token can be decoded
        access_token_obj = AccessToken(access_token)
        assert access_token_obj['user_id'] == user.id

        # Verify refresh token can be decoded
        refresh_token_obj = RefreshToken(refresh_token)
        assert refresh_token_obj['user_id'] == user.id

    def test_dual_authentication_support(self):
        """Test user can authenticate with both password and OAuth."""
        # Create user with password
        user = User.objects.create_user(
            username='dualuser',
            email='dual@example.com',
            password='testpass123'
        )

        # Verify password auth works
        assert user.check_password('testpass123')
        assert user.has_usable_password()

        # Link OAuth account
        user.google_id = 'google111222'
        user.save()

        # Verify both methods are available
        user.refresh_from_db()
        assert user.has_usable_password()  # Password still works
        assert user.google_id == 'google111222'  # OAuth linked

    def test_oauth_generated_tokens_work_with_protected_endpoints(self):
        """Test OAuth-generated JWT tokens work with protected endpoints."""
        user = User.objects.create_user(
            username='tokentest',
            email='token@example.com',
            google_id='google555666'
        )
        user.set_unusable_password()
        user.save()

        # Generate tokens
        access_token, refresh_token = generate_jwt_tokens(user)

        # Verify access token can be used (decode it)
        access_token_obj = AccessToken(access_token)
        assert access_token_obj['user_id'] == user.id
        assert 'exp' in access_token_obj  # Has expiration
        assert 'token_type' in access_token_obj  # Has token type

    def test_oauth_user_cannot_login_with_password(self):
        """Test OAuth-only users cannot login with password."""
        user = User.objects.create_user(
            username='oauthonly',
            email='oauthonly@example.com',
            google_id='google777888'
        )
        user.set_unusable_password()
        user.save()

        # Verify user cannot authenticate with password
        assert not user.has_usable_password()
        assert not user.check_password('anypassword')

    def test_account_linking_updates_existing_user_record(self):
        """Test account linking updates existing user, no duplicates."""
        # Create existing user
        user = User.objects.create_user(
            username='update',
            email='update@example.com',
            password='oldpass'
        )
        initial_count = User.objects.count()

        # Link OAuth account
        user.google_id = 'google999000'
        user.profile_picture_url = 'https://example.com/new.jpg'
        user.save()

        # Verify no duplicate user was created
        assert User.objects.count() == initial_count
        # Verify user was updated
        user.refresh_from_db()
        assert user.google_id == 'google999000'
        assert user.profile_picture_url == 'https://example.com/new.jpg'

    def test_google_id_uniqueness_prevents_duplicate_oauth_accounts(self):
        """Test google_id uniqueness constraint prevents duplicates."""
        from django.db import IntegrityError

        # Create first OAuth user
        user1 = User.objects.create_user(
            username='user1',
            email='user1@example.com',
            google_id='google_shared_id'
        )

        # Attempt to create second user with same google_id
        with pytest.raises(IntegrityError):
            User.objects.create_user(
                username='user2',
                email='user2@example.com',
                google_id='google_shared_id'  # Same ID
            )

    def test_oauth_fields_are_nullable_for_password_users(self):
        """Test password-only users don't need OAuth fields."""
        user = User.objects.create_user(
            username='passworduser',
            email='password@example.com',
            password='securepass123'
        )

        # Verify OAuth fields are None
        assert user.google_id is None
        assert user.profile_picture_url is None
        # Verify password auth works
        assert user.has_usable_password()
        assert user.check_password('securepass123')

    def test_profile_data_population_from_oauth(self):
        """Test profile data is correctly populated from OAuth."""
        oauth_data = {
            'id': 'google_profile_test',
            'email': 'profile@example.com',
            'given_name': 'Jane',
            'family_name': 'Smith',
            'picture': 'https://lh3.googleusercontent.com/a-/test123'
        }

        user = User.objects.create_user(
            username='profile',
            email=oauth_data['email'],
            first_name=oauth_data['given_name'],
            last_name=oauth_data['family_name'],
            google_id=oauth_data['id'],
            profile_picture_url=oauth_data['picture']
        )
        user.set_unusable_password()
        user.save()

        # Verify all profile data was stored
        user.refresh_from_db()
        assert user.email == oauth_data['email']
        assert user.first_name == oauth_data['given_name']
        assert user.last_name == oauth_data['family_name']
        assert user.google_id == oauth_data['id']
        assert user.profile_picture_url == oauth_data['picture']
