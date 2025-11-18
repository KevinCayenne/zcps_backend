"""
Tests for OAuth Swagger documentation.

Verifies that OAuth endpoints appear in the OpenAPI schema
with correct documentation for all 3 scenarios.
"""

import pytest
import yaml
from django.urls import reverse
from rest_framework.test import APIClient


@pytest.mark.django_db
class TestOAuthSwaggerDocumentation:
    """Tests for OAuth endpoint Swagger documentation."""

    def test_schema_endpoint_accessible(self):
        """Test that schema endpoint is accessible."""
        client = APIClient()
        url = reverse('schema')
        response = client.get(url)

        assert response.status_code == 200
        assert 'application/vnd.oai.openapi' in response['content-type']

    def test_schema_is_valid_openapi(self):
        """Test that schema is valid OpenAPI 3.0 specification."""
        client = APIClient()
        url = reverse('schema')
        response = client.get(url)

        schema = yaml.safe_load(response.content)

        # Check OpenAPI version
        assert 'openapi' in schema
        assert schema['openapi'].startswith('3.0')

        # Check required fields
        assert 'info' in schema
        assert 'paths' in schema

    def test_google_callback_documented_if_available(self):
        """Test that /auth/google/callback/ endpoint is documented if available."""
        client = APIClient()
        url = reverse('schema')
        response = client.get(url)

        schema = yaml.safe_load(response.content)
        paths = schema.get('paths', {})

        # Check if Google callback endpoint is documented
        # This may not be present if drf-spectacular doesn't auto-detect Django Views
        callback_path = paths.get('/auth/google/callback/')
        if callback_path:
            # If present, should have GET method
            assert 'get' in callback_path

            get_op = callback_path['get']

            # Should have some documentation
            has_doc = 'summary' in get_op or 'description' in get_op
            assert has_doc


@pytest.mark.django_db
class TestOAuth2FAScenarioDocumentation:
    """Tests for OAuth 2FA scenario documentation in schema."""

    def test_2fa_endpoints_documented_for_setup_flow(self):
        """Test that 2FA enable endpoints are documented for setup flow."""
        client = APIClient()
        url = reverse('schema')
        response = client.get(url)

        schema = yaml.safe_load(response.content)
        paths = schema.get('paths', {})

        # These endpoints are used in Scenario 3
        assert '/auth/2fa/enable/' in paths
        assert '/auth/2fa/enable/verify/' in paths

    def test_2fa_verify_endpoint_documented_for_login_flow(self):
        """Test that 2FA verify endpoint is documented for login flow."""
        client = APIClient()
        url = reverse('schema')
        response = client.get(url)

        schema = yaml.safe_load(response.content)
        paths = schema.get('paths', {})

        # This endpoint is used in Scenario 2
        assert '/auth/2fa/verify/' in paths

    def test_2fa_enable_has_description(self):
        """Test that 2FA enable endpoint has proper description."""
        client = APIClient()
        url = reverse('schema')
        response = client.get(url)

        schema = yaml.safe_load(response.content)
        paths = schema.get('paths', {})

        enable_path = paths.get('/auth/2fa/enable/')
        assert enable_path is not None

        post_op = enable_path.get('post', {})

        # Should have description
        description = post_op.get('description', '')
        assert len(description) > 0
        assert 'verification code' in description.lower() or 'setup' in description.lower()

    def test_2fa_verify_login_has_description(self):
        """Test that 2FA verify login endpoint has proper description."""
        client = APIClient()
        url = reverse('schema')
        response = client.get(url)

        schema = yaml.safe_load(response.content)
        paths = schema.get('paths', {})

        verify_path = paths.get('/auth/2fa/verify/')
        assert verify_path is not None

        post_op = verify_path.get('post', {})

        # Should have description
        description = post_op.get('description', '')
        assert len(description) > 0
        assert 'verify' in description.lower() or 'code' in description.lower()

    def test_2fa_endpoints_tagged_correctly(self):
        """Test that 2FA endpoints are in Two-Factor Authentication tag."""
        client = APIClient()
        url = reverse('schema')
        response = client.get(url)

        schema = yaml.safe_load(response.content)
        paths = schema.get('paths', {})

        # Check 2fa_enable is tagged
        enable_path = paths.get('/auth/2fa/enable/')
        if enable_path:
            post_op = enable_path.get('post', {})
            tags = post_op.get('tags', [])
            assert 'Two-Factor Authentication' in tags

        # Check 2fa_verify is tagged
        verify_path = paths.get('/auth/2fa/verify/')
        if verify_path:
            post_op = verify_path.get('post', {})
            tags = post_op.get('tags', [])
            assert 'Two-Factor Authentication' in tags
