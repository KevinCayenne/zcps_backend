# Django Authentication Boilerplate

A production-ready Django REST Framework boilerplate with comprehensive authentication features including JWT tokens, email verification, password management, and Google OAuth 2.0 integration.

## Features

### Authentication & Authorization
- User registration with email and password
- JWT-based authentication with access and refresh tokens
- Token blacklisting for secure logout
- Email or username login support
- Google OAuth 2.0 authentication (Sign in with Google)
- Dual authentication support (password + OAuth)
- Automatic account linking by email for OAuth users
- **Two-Factor Authentication (2FA)** with email verification codes
- Optional 2FA enforcement for all users (configurable via Django admin)
- Temporary token system for 2FA verification flow
- Setup tokens for mandatory 2FA enrollment

### Password Management
- Password reset via email with secure tokens
- Password change for authenticated users
- Optional JWT token blacklisting on password change
- Configurable password reset token expiration

### Email Features
- Email activation system
- Resend activation email functionality
- Password reset confirmation emails
- Password change notification emails
- 2FA verification code delivery via email

### User Management
- Custom User model with email as primary identifier
- User profile endpoints (view, update, delete)
- Phone number field with international format support
- OAuth profile data storage (Google ID, profile picture)
- User listing with proper permissions
- 2FA settings per user (opt-in/opt-out, preferred delivery method)
- Database-configurable 2FA policies via Django admin

### API Documentation
- Interactive Swagger UI documentation
- ReDoc alternative documentation
- OpenAPI 3.0 schema generation
- Automatic endpoint documentation
- Bearer token authentication in docs

### Security
- CSRF protection
- Password validation
- Secure token storage
- Token expiration and refresh
- OAuth state validation
- Configurable security settings
- Two-factor authentication with cryptographically secure codes
- Temporary token restrictions via middleware
- 2FA enforcement policies for enhanced security

## Quick Start

### 1. Clone and Setup

```bash
# Clone repository
git clone <repository-url>
cd django_boilerplate

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment variables
cp .env.example .env
# Edit .env with your configuration

# Install pre-commit hooks
pre-commit install
```

### 2. Configure Google OAuth (Optional)

Follow the [Google OAuth Setup Guide](docs/google-oauth-setup.md) to:
1. Create a Google Cloud Project
2. Enable Google+ API
3. Create OAuth 2.0 credentials
4. Configure authorized redirect URIs
5. Add credentials to your `.env` file

### 3. Database Setup

```bash
# Run migrations
python manage.py migrate

# Create superuser (optional)
python manage.py createsuperuser
```

### 4. Run Development Server

```bash
python manage.py runserver
```

The API will be available at `http://localhost:8000/`

## API Endpoints

### Authentication Endpoints

#### Traditional Authentication
- `POST /auth/users/` - Register new user
- `POST /auth/jwt/create/` - Login (obtain JWT tokens)
- `POST /auth/jwt/refresh/` - Refresh access token
- `POST /auth/jwt/verify/` - Verify token validity
- `POST /auth/logout/` - Logout and blacklist tokens

#### Google OAuth
- `GET /auth/google/` - Initiate Google OAuth flow
- `GET /auth/google/callback/` - OAuth callback (handled automatically)

#### Email & Activation
- `POST /auth/users/activation/` - Activate user account
- `POST /auth/users/resend_activation/` - Resend activation email

#### Password Management
- `POST /auth/users/reset_password/` - Request password reset
- `POST /auth/users/reset_password_confirm/` - Confirm password reset
- `POST /auth/users/set_password/` - Change password (authenticated)

#### Two-Factor Authentication
- `POST /auth/2fa/enable/` - Enable 2FA and request verification code
- `POST /auth/2fa/enable/verify/` - Verify code and complete 2FA setup
- `POST /auth/2fa/disable/` - Disable 2FA for account
- `GET /auth/2fa/status/` - Check 2FA status for current user
- `POST /auth/2fa/verify/` - Verify 2FA code during login
- `POST /auth/2fa/resend/` - Resend 2FA verification code

### User Endpoints

- `GET /auth/users/me/` - Get current user profile
- `PUT /auth/users/me/` - Update current user profile
- `PATCH /auth/users/me/` - Partial update current user
- `DELETE /auth/users/me/` - Delete current user account
- `GET /auth/users/` - List all users (admin only)
- `GET /auth/users/{id}/` - Get user by ID (admin only)

### Documentation

- `GET /api/docs/` - Swagger UI documentation
- `GET /api/redoc/` - ReDoc documentation
- `GET /api/schema/` - OpenAPI schema (JSON)

## Google OAuth Integration

### Backend Setup

1. Follow the [Google OAuth Setup Guide](docs/google-oauth-setup.md)
2. Configure environment variables in `.env`:
   ```env
   GOOGLE_OAUTH_CLIENT_ID=your-client-id
   GOOGLE_OAUTH_CLIENT_SECRET=your-client-secret
   GOOGLE_OAUTH_SUCCESS_REDIRECT_URL=http://localhost:3000/auth/callback
   GOOGLE_OAUTH_ERROR_REDIRECT_URL=http://localhost:3000/auth/error
   ```

### Frontend Integration

Follow the [Frontend Integration Guide](docs/google-oauth-frontend-integration.md) to:
1. Initiate OAuth flow from your frontend
2. Handle callback with JWT tokens
3. Handle error scenarios
4. Make authenticated API requests

### OAuth Flow Summary

1. User clicks "Sign in with Google" button
2. Frontend redirects to `GET /auth/google/`
3. User authorizes on Google's consent screen
4. Backend receives authorization code
5. Backend exchanges code for Google access token
6. Backend creates/links user account
7. Backend generates JWT tokens
8. Backend redirects to frontend with tokens
9. Frontend stores tokens and makes authenticated requests

### Account Linking

- If a user signs in with Google and an account with that email already exists, the Google account is automatically linked
- Users can use both password login and Google OAuth to access the same account
- OAuth users can set a password later to enable password login

## Configuration

### Environment Variables

Key configuration options in `.env`:

```env
# Django
SECRET_KEY=your-secret-key
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Frontend
FRONTEND_URL=http://localhost:3000

# JWT Tokens
JWT_ACCESS_TOKEN_MINUTES=15
JWT_REFRESH_TOKEN_DAYS=7

# Email
SEND_ACTIVATION_EMAIL=True

# Password Management
PASSWORD_RESET_TIMEOUT=86400
BLACKLIST_TOKENS_ON_PASSWORD_CHANGE=False

# Two-Factor Authentication
# All 2FA settings are managed via Django admin at /admin/users/twofactorsettings/
# No environment variables needed - configure in database

# Google OAuth
GOOGLE_OAUTH_CLIENT_ID=your-google-client-id
GOOGLE_OAUTH_CLIENT_SECRET=your-google-client-secret
GOOGLE_OAUTH_SUCCESS_REDIRECT_URL=http://localhost:3000/auth/callback
GOOGLE_OAUTH_ERROR_REDIRECT_URL=http://localhost:3000/auth/error
```

See `.env.example` for all available options.

### Two-Factor Authentication Configuration

2FA settings are managed via Django admin (not environment variables):

1. Access Django admin: `http://localhost:8000/admin/users/twofactorsettings/`
2. Configure settings:
   - `enforce_2fa_for_all_users` - Require all users to enable 2FA (default: False)
   - `default_2fa_method` - Default delivery method for codes (default: EMAIL)
   - `code_expiration_seconds` - How long codes are valid (default: 600 = 10 min)
   - `max_failed_attempts` - Maximum failed verification attempts (default: 5)
   - `temporary_token_lifetime_minutes` - Lifetime of temporary tokens (default: 10 min)

## Testing

Run the test suite:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=users

# Run specific test file
pytest users/tests/test_oauth_endpoints.py

# Run with verbose output
pytest -v
```

## Project Structure

```
django_boilerplate/
├── config/                 # Project configuration
│   ├── settings/          # Settings modules
│   │   ├── base.py       # Base settings
│   │   ├── development.py
│   │   ├── testing.py
│   │   └── production.py
│   ├── urls.py           # Main URL configuration
│   └── wsgi.py
├── users/                 # Users app
│   ├── models.py         # Custom User model with 2FA fields
│   ├── serializers.py    # DRF serializers
│   ├── views.py          # User management API views
│   ├── jwt_views.py      # JWT authentication views with 2FA
│   ├── twofactor_views.py # 2FA setup and verification views
│   ├── twofactor_utils.py # 2FA utility functions
│   ├── backends.py       # Custom auth backends
│   ├── oauth_adapters.py # OAuth adapters and token generators
│   ├── oauth_views.py    # OAuth views
│   ├── middleware.py     # 2FA enforcement and token restriction
│   ├── utils.py          # Utility functions
│   ├── admin.py          # Django admin configuration
│   ├── tests/            # Test suite
│   └── migrations/
├── docs/                  # Documentation
│   ├── google-oauth-setup.md
│   └── google-oauth-frontend-integration.md
├── .env.example          # Environment variables template
├── requirements.txt      # Python dependencies
├── manage.py
└── README.md
```

## Tech Stack

- **Django** 4.2.11 - Web framework
- **Django REST Framework** 3.14.0 - API framework
- **Djoser** 2.2.2 - Authentication endpoints
- **djangorestframework-simplejwt** 5.3.1 - JWT authentication
- **django-allauth** 0.57.0 - OAuth provider integration
- **dj-rest-auth** 5.0.2 - Social authentication with DRF
- **django-solo** 2.3.0 - Singleton model for 2FA settings
- **django-cors-headers** 4.9.0 - CORS support for frontend integration
- **drf-spectacular** 0.27.2 - API documentation
- **pytest** & **pytest-django** - Testing framework

## Security Features

- JWT tokens with configurable expiration
- Token blacklisting for logout
- Password validation with Django validators
- CSRF protection enabled
- Secure password hashing (PBKDF2)
- OAuth state validation
- Minimal OAuth scopes (openid, email, profile)
- Unusable passwords for OAuth-only users
- Two-factor authentication with cryptographically secure 6-digit codes
- Temporary token restrictions enforced via middleware
- 2FA enforcement policies configurable per deployment
- Separate setup tokens for mandatory 2FA enrollment

## Production Deployment

For production deployment:

1. Set `DEBUG=False` in `.env`
2. Configure proper `ALLOWED_HOSTS`
3. Use PostgreSQL database (configure `DATABASE_URL`)
4. Set up email backend (SMTP configuration)
5. Configure HTTPS redirect and secure cookies
6. Use environment-specific settings (`production.py`)
7. Create separate Google OAuth credentials for production
8. Update OAuth redirect URIs to production URLs
9. Enable security middleware
10. Set up static file serving
11. Configure logging

See [Production Settings](config/settings/production.py) for production configuration.

## Documentation

### Setup & Integration Guides
- [Google OAuth Setup Guide](docs/google-oauth-setup.md) - Set up Google OAuth credentials
- [Frontend Integration Guide](docs/google-oauth-frontend-integration.md) - Integrate OAuth with your frontend

### API Documentation & Testing
- [Swagger API Reference](docs/swagger-api-reference.md) - Complete guide to using Swagger UI for testing
- [Manual Testing Workflows](docs/manual-testing-workflows.md) - Step-by-step testing scenarios for all endpoints
- [Interactive Swagger UI](http://localhost:8000/api/docs/) - Live API documentation (requires server running)
- [ReDoc Documentation](http://localhost:8000/api/redoc/) - Alternative API documentation format

## Support

For issues and questions:
- Check the [Manual Testing Workflows](docs/manual-testing-workflows.md) for testing guidance
- Review the [Swagger API Reference](docs/swagger-api-reference.md) for endpoint usage
- Check the [Google OAuth Setup Guide](docs/google-oauth-setup.md) for OAuth-related issues
- Review server logs for detailed error messages
- Consult the API documentation at `/api/docs/`
- Check environment variable configuration

## License

This project is provided as a boilerplate for building authentication systems.

## Contributing

Contributions are welcome! Please ensure:
- All tests pass (`pytest`)
- Code follows existing patterns
- Documentation is updated
- Security best practices are followed
