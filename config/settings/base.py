"""
Django base settings for config project.

This file contains shared settings used across all environments.
Environment-specific settings are in development.py, testing.py, and production.py.
"""

from pathlib import Path
from datetime import timedelta
from decouple import config

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent.parent


# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('SECRET_KEY', default='django-insecure-pdx_)j9t%_135!=8w@t8)gur2sd$+4_3mezx8%0se)wmcn)8zr')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = config('DEBUG', default=True, cast=bool)

ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='', cast=lambda v: [s.strip() for s in v.split(',') if s.strip()])


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',  # Required by allauth

    # Third-party apps
    'drf_spectacular',
    'rest_framework',
    'djoser',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'solo',  # Django Solo for singleton models

    # Allauth packages (must come before dj_rest_auth)
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',

    # dj-rest-auth packages
    'dj_rest_auth',
    'dj_rest_auth.registration',

    # Local apps
    'users',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'allauth.account.middleware.AccountMiddleware',  # Required by allauth
    'users.middleware.TwoFactorEnforcementMiddleware',  # 2FA enforcement middleware
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Custom User Model
AUTH_USER_MODEL = 'users.User'


# Authentication backends
AUTHENTICATION_BACKENDS = [
    'users.backends.EmailOrUsernameModelBackend',
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',  # OAuth backend
]


# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Password Management Configuration
# Password reset token expiration time in seconds (24 hours default)
PASSWORD_RESET_TIMEOUT = config('PASSWORD_RESET_TIMEOUT', default=86400, cast=int)

# Frontend URL for constructing password reset and email verification links
FRONTEND_URL = config('FRONTEND_URL', default='http://localhost:3000')

# JWT token blacklisting on password change (optional, default: False)
# When True, all JWT tokens are blacklisted when user changes password
BLACKLIST_TOKENS_ON_PASSWORD_CHANGE = config('BLACKLIST_TOKENS_ON_PASSWORD_CHANGE', default=False, cast=bool)

# Email 2FA enforcement setting (placeholder for future roadmap item 7)
# This setting is reserved for future multi-factor authentication implementation
EMAIL_2FA_ENFORCEMENT = config('EMAIL_2FA_ENFORCEMENT', default=False, cast=bool)


# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = 'static/'


# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# Email Configuration
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='noreply@example.com')


# Django REST Framework Configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
}


# Simple JWT Configuration
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=config('JWT_ACCESS_TOKEN_MINUTES', default=15, cast=int)),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=config('JWT_REFRESH_TOKEN_DAYS', default=7, cast=int)),
    'ROTATE_REFRESH_TOKENS': False,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
}


# Djoser Configuration
DJOSER = {
    'SEND_ACTIVATION_EMAIL': config('SEND_ACTIVATION_EMAIL', default=True, cast=bool),
    'SEND_CONFIRMATION_EMAIL': False,
    'PASSWORD_CHANGED_EMAIL_CONFIRMATION': True,
    'ACTIVATION_URL': 'activate/{uid}/{token}',
    'PASSWORD_RESET_CONFIRM_URL': 'password/reset/confirm/{uid}/{token}',
    'USERNAME_RESET_CONFIRM_URL': 'username/reset/confirm/{uid}/{token}',
    'USER_CREATE_PASSWORD_RETYPE': False,
    'SET_PASSWORD_RETYPE': False,
    'USERNAME_CHANGED_EMAIL_CONFIRMATION': False,
    'LOGIN_FIELD': 'email',
    'TOKEN_MODEL': None,  # Using JWT instead of Djoser tokens
    'SERIALIZERS': {
        'user_create': 'users.serializers.UserCreateSerializer',
        'user': 'users.serializers.UserSerializer',
        'current_user': 'users.serializers.UserSerializer',
    },
    'EMAIL': {
        'activation': 'users.email.ActivationEmail',
        'confirmation': 'users.email.ConfirmationEmail',
        'password_reset': 'users.email.PasswordResetEmail',
        'password_changed_confirmation': 'users.email.PasswordChangedConfirmationEmail',
    },
    'PERMISSIONS': {
        'user': ['rest_framework.permissions.IsAdminUser'],  # GET /auth/users/ - Admin only
        'user_list': ['rest_framework.permissions.IsAdminUser'],  # GET /auth/users/ - Admin only
        'user_create': ['rest_framework.permissions.AllowAny'],  # POST /auth/users/ - Public registration
        'user_delete': ['rest_framework.permissions.IsAdminUser'],  # DELETE /auth/users/{id}/ - Admin only
        'set_password': ['rest_framework.permissions.IsAuthenticated'],  # POST /auth/users/set_password/ - Current user
        'username_reset': ['rest_framework.permissions.AllowAny'],  # POST /auth/users/reset_username/ - Public
        'username_reset_confirm': ['rest_framework.permissions.AllowAny'],  # POST /auth/users/reset_username_confirm/ - Public
        'set_username': ['rest_framework.permissions.IsAuthenticated'],  # POST /auth/users/set_username/ - Current user
        'activation': ['rest_framework.permissions.AllowAny'],  # POST /auth/users/activation/ - Public
        'resend_activation': ['rest_framework.permissions.AllowAny'],  # POST /auth/users/resend_activation/ - Public
        'reset_password': ['rest_framework.permissions.AllowAny'],  # POST /auth/users/reset_password/ - Public
        'reset_password_confirm': ['rest_framework.permissions.AllowAny'],  # POST /auth/users/reset_password_confirm/ - Public
    },
}


# drf-spectacular Configuration
SPECTACULAR_SETTINGS = {
    'TITLE': 'Django Authentication Boilerplate API',
    'VERSION': '1.0.0',
    'DESCRIPTION': 'API documentation for Django authentication boilerplate with JWT token support',
    'SERVE_INCLUDE_SCHEMA': False,
    'COMPONENT_SPLIT_REQUEST': True,
    'SCHEMA_TAGS_SORTING': 'alpha',
    'OPERATION_SORTING': 'alpha',
    'APPEND_COMPONENTS': {
        'securitySchemes': {
            'bearerAuth': {
                'type': 'http',
                'scheme': 'bearer',
                'bearerFormat': 'JWT',
            }
        }
    },
    'SECURITY': [
        {
            'bearerAuth': []
        }
    ],
}


# Django Sites Framework (required by allauth)
SITE_ID = 1


# Django Allauth Configuration
SOCIALACCOUNT_AUTO_SIGNUP = True  # Auto-create users on OAuth
SOCIALACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_EMAIL_VERIFICATION = 'none'  # No email verification for OAuth users
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_AUTHENTICATION_METHOD = 'email'
ACCOUNT_USERNAME_REQUIRED = False
SOCIALACCOUNT_ADAPTER = 'users.oauth_adapters.CustomSocialAccountAdapter'  # Custom adapter


# Google OAuth Configuration
SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'SCOPE': [
            'openid',
            'profile',
            'email',
        ],
        'APP': {
            'client_id': config('GOOGLE_OAUTH_CLIENT_ID', default=''),
            'secret': config('GOOGLE_OAUTH_CLIENT_SECRET', default=''),
            'key': ''
        },
        'AUTH_PARAMS': {
            'access_type': 'online',
        }
    }
}

# Google OAuth redirect URLs
GOOGLE_OAUTH_SUCCESS_REDIRECT_URL = config('GOOGLE_OAUTH_SUCCESS_REDIRECT_URL', default='http://localhost:3000/auth/callback')
GOOGLE_OAUTH_ERROR_REDIRECT_URL = config('GOOGLE_OAUTH_ERROR_REDIRECT_URL', default='http://localhost:3000/auth/error')


# dj-rest-auth Configuration
REST_USE_JWT = True  # Enable JWT tokens for OAuth
JWT_AUTH_COOKIE = None  # Use Authorization header instead of cookies
JWT_AUTH_REFRESH_COOKIE = None
REST_SESSION_LOGIN = False  # API-only, no session-based auth

REST_AUTH = {
    'USE_JWT': True,
    'JWT_AUTH_COOKIE': None,
    'JWT_AUTH_REFRESH_COOKIE': None,
    'SESSION_LOGIN': False,
    'TOKEN_MODEL': None,  # We're using JWT tokens, not DRF tokens
}


# Two-Factor Authentication Configuration
# DEPRECATED: These settings will be migrated to database-based TwoFactorSettings model
REQUIRE_2FA_FOR_ALL_USERS = config('REQUIRE_2FA_FOR_ALL_USERS', default=False, cast=bool)
TWOFACTOR_CODE_EXPIRATION = config('TWOFACTOR_CODE_EXPIRATION', default=600, cast=int)  # 10 minutes
TWOFACTOR_CODE_LENGTH = config('TWOFACTOR_CODE_LENGTH', default=6, cast=int)
TWOFACTOR_MAX_FAILED_ATTEMPTS = config('TWOFACTOR_MAX_FAILED_ATTEMPTS', default=5, cast=int)
TWOFACTOR_TEMPORARY_TOKEN_LIFETIME = config('TWOFACTOR_TEMPORARY_TOKEN_LIFETIME', default=10, cast=int)  # minutes
