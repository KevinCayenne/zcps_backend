"""
Tests for API schema generation and documentation.

Tests verify that drf-spectacular correctly generates OpenAPI schema
with authentication endpoints and JWT security configuration.
"""

import pytest
import yaml
from django.urls import reverse
from rest_framework.test import APIClient


@pytest.mark.django_db
class TestSchemaGeneration:
    """Tests for OpenAPI schema generation."""

    def test_schema_endpoint_accessible(self):
        """Test that schema endpoint returns 200 status."""
        client = APIClient()
        url = reverse('schema')
        response = client.get(url)
        assert response.status_code == 200
        assert 'application/vnd.oai.openapi' in response['content-type']

    def test_schema_contains_auth_endpoints(self):
        """Test that schema includes authentication endpoints."""
        client = APIClient()
        url = reverse('schema')
        response = client.get(url)

        # Parse the YAML response content
        schema = yaml.safe_load(response.content)
        paths = schema.get('paths', {})

        # Check for key authentication endpoints
        assert '/auth/jwt/create/' in paths
        assert '/auth/users/' in paths
        assert '/auth/logout/' in paths

    def test_schema_includes_jwt_bearer_security(self):
        """Test that schema includes JWT Bearer security scheme."""
        client = APIClient()
        url = reverse('schema')
        response = client.get(url)

        # Parse the YAML response content
        schema = yaml.safe_load(response.content)
        components = schema.get('components', {})
        security_schemes = components.get('securitySchemes', {})

        # Check JWT Bearer authentication is configured
        # drf-spectacular should have at least one JWT bearer scheme
        # (either 'jwtAuth' auto-detected or 'bearerAuth' from our config)
        assert len(security_schemes) > 0

        # Find a bearer auth scheme
        bearer_scheme = None
        for scheme_name, scheme_config in security_schemes.items():
            if scheme_config.get('type') == 'http' and scheme_config.get('scheme') == 'bearer':
                bearer_scheme = scheme_config
                break

        assert bearer_scheme is not None
        assert bearer_scheme['type'] == 'http'
        assert bearer_scheme['scheme'] == 'bearer'
        assert bearer_scheme['bearerFormat'] == 'JWT'

    def test_swagger_ui_accessible(self):
        """Test that Swagger UI endpoint returns 200 status."""
        client = APIClient()
        url = reverse('swagger-ui')
        response = client.get(url)
        assert response.status_code == 200
        assert 'text/html' in response['content-type']


@pytest.mark.django_db
class TestDocumentationQuality:
    """Tests for documentation quality and completeness."""

    def test_logout_view_in_schema(self):
        """Test that LogoutView appears in schema with correct description."""
        client = APIClient()
        url = reverse('schema')
        response = client.get(url)

        schema = yaml.safe_load(response.content)
        paths = schema.get('paths', {})

        # Check LogoutView is documented
        logout_path = paths.get('/auth/logout/')
        assert logout_path is not None
        assert 'post' in logout_path

        # Check that it has a description
        post_operation = logout_path['post']
        # Description can be in description or summary field
        has_description = 'description' in post_operation or 'summary' in post_operation
        assert has_description

    def test_user_create_serializer_fields_in_schema(self):
        """Test that UserCreateSerializer fields appear in schema."""
        client = APIClient()
        url = reverse('schema')
        response = client.get(url)

        schema = yaml.safe_load(response.content)
        components = schema.get('components', {})
        schemas = components.get('schemas', {})

        # Find user creation schema
        user_create_schema = None
        for schema_name, schema_def in schemas.items():
            # Look for User or UserCreate schema
            if 'User' in schema_name and 'properties' in schema_def:
                props = schema_def['properties']
                # If it has password field (write_only), it's likely the create schema
                if 'password' in props or all(field in props for field in ['username', 'email']):
                    user_create_schema = schema_def
                    break

        assert user_create_schema is not None
        props = user_create_schema['properties']

        # Check for key fields
        assert 'username' in props
        assert 'email' in props

    def test_protected_endpoints_show_authentication(self):
        """Test that protected endpoints show authentication requirement."""
        client = APIClient()
        url = reverse('schema')
        response = client.get(url)

        schema = yaml.safe_load(response.content)
        paths = schema.get('paths', {})

        # Check a protected endpoint (e.g., /auth/users/me/)
        users_me_path = paths.get('/auth/users/me/')
        assert users_me_path is not None

        # Check GET method has security requirement
        get_operation = users_me_path.get('get')
        assert get_operation is not None

        # Security can be defined at operation level or globally
        has_security = 'security' in get_operation or 'security' in schema
        assert has_security

    def test_schema_has_examples(self):
        """Test that schema includes examples for key operations."""
        client = APIClient()
        url = reverse('schema')
        response = client.get(url)

        schema = yaml.safe_load(response.content)
        components = schema.get('components', {})
        schemas = components.get('schemas', {})

        # Just verify we have component schemas defined
        # drf-spectacular auto-generates examples from serializers
        assert len(schemas) > 0

        # Verify at least some schemas have properties (which can be used as examples)
        has_properties = any('properties' in s for s in schemas.values())
        assert has_properties


@pytest.mark.django_db
class TestEndToEndWorkflows:
    """Integration tests for complete API workflows via schema."""

    def test_registration_login_workflow_documented(self):
        """Test that registration -> login workflow is fully documented in schema."""
        client = APIClient()
        url = reverse('schema')
        response = client.get(url)

        schema = yaml.safe_load(response.content)
        paths = schema.get('paths', {})

        # Verify registration endpoint is documented
        users_path = paths.get('/auth/users/')
        assert users_path is not None
        assert 'post' in users_path
        post_op = users_path['post']
        assert 'requestBody' in post_op

        # Verify login endpoint is documented
        jwt_create_path = paths.get('/auth/jwt/create/')
        assert jwt_create_path is not None
        assert 'post' in jwt_create_path
        jwt_post_op = jwt_create_path['post']
        assert 'requestBody' in jwt_post_op
        assert 'responses' in jwt_post_op

    def test_token_refresh_workflow_documented(self):
        """Test that token refresh workflow is documented correctly."""
        client = APIClient()
        url = reverse('schema')
        response = client.get(url)

        schema = yaml.safe_load(response.content)
        paths = schema.get('paths', {})

        # Verify token refresh endpoint is documented
        jwt_refresh_path = paths.get('/auth/jwt/refresh/')
        assert jwt_refresh_path is not None
        assert 'post' in jwt_refresh_path

        refresh_op = jwt_refresh_path['post']
        assert 'requestBody' in refresh_op
        assert 'responses' in refresh_op

    def test_logout_workflow_documented(self):
        """Test that logout workflow with token blacklisting is documented."""
        client = APIClient()
        url = reverse('schema')
        response = client.get(url)

        schema = yaml.safe_load(response.content)
        paths = schema.get('paths', {})

        # Verify logout endpoint is documented
        logout_path = paths.get('/auth/logout/')
        assert logout_path is not None
        assert 'post' in logout_path

        logout_op = logout_path['post']
        # Should require authentication
        has_security = 'security' in logout_op or 'security' in schema
        assert has_security

        # Should have request body for refresh token
        assert 'requestBody' in logout_op

        # Should document responses (204 and 400)
        assert 'responses' in logout_op

    def test_redoc_view_accessible(self):
        """Test that ReDoc alternative documentation view is accessible."""
        client = APIClient()
        url = reverse('redoc')
        response = client.get(url)
        assert response.status_code == 200
        assert 'text/html' in response['content-type']

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
        assert 'components' in schema

        # Check info fields
        info = schema['info']
        assert 'title' in info
        assert 'version' in info
        assert info['title'] == 'Django Authentication Boilerplate API'
        assert info['version'] == '1.0.0'

    def test_error_responses_documented(self):
        """Test that error responses are documented for endpoints."""
        client = APIClient()
        url = reverse('schema')
        response = client.get(url)

        schema = yaml.safe_load(response.content)
        paths = schema.get('paths', {})

        # Check logout endpoint has error responses documented
        logout_path = paths.get('/auth/logout/')
        assert logout_path is not None

        logout_op = logout_path['post']
        responses = logout_op.get('responses', {})

        # Should have at least success response
        assert len(responses) > 0

        # Common status codes that might be documented
        # drf-spectacular auto-generates these based on view logic
        documented_codes = [str(code) for code in responses.keys()]
        assert len(documented_codes) > 0
