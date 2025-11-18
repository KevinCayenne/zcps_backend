"""
Django base settings for config project.

This file contains shared settings used across all environments.
Environment-specific settings are in development.py, testing.py, and production.py.
"""

import os
from pathlib import Path
from datetime import timedelta
from dotenv import load_dotenv

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Load secrets from .env file
load_dotenv(BASE_DIR / '.env')

# Django secret key
SECRET_KEY = os.environ.get('SECRET_KEY', 'django-insecure-pdx_)j9t%_135!=8w@t8)gur2sd$+4_3mezx8%0se)wmcn)8zr')

# Database URL
DATABASE_URL = os.environ.get('DATABASE_URL', '')

# Google OAuth credentials
GOOGLE_OAUTH_CLIENT_ID = os.environ.get('GOOGLE_OAUTH_CLIENT_ID', '')
GOOGLE_OAUTH_CLIENT_SECRET = os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET', '')

# Email password for SMTP
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', '')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

# Allowed hosts - override in environment-specific settings
ALLOWED_HOSTS = []


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
    'corsheaders',  # CORS headers support
    'drf_spectacular',
    'rest_framework',
    'djoser',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',

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
    'corsheaders.middleware.CorsMiddleware',  # CORS middleware (must be before CommonMiddleware)
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'allauth.account.middleware.AccountMiddleware',  # Required by allauth
    'users.middleware.TemporaryTokenRestrictionMiddleware',  # Restrict temporary 2FA tokens
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
# Password reset token expiration time in seconds (24 hours)
PASSWORD_RESET_TIMEOUT = 86400

# Frontend URL for constructing password reset and email verification links
FRONTEND_URL = 'http://localhost:3000'

# JWT token blacklisting on password change
# When True, all JWT tokens are blacklisted when user changes password
BLACKLIST_TOKENS_ON_PASSWORD_CHANGE = False


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
DEFAULT_FROM_EMAIL = 'noreply@example.com'


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
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
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
    'SEND_ACTIVATION_EMAIL': True,
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
            'client_id': GOOGLE_OAUTH_CLIENT_ID,
            'secret': GOOGLE_OAUTH_CLIENT_SECRET,
            'key': ''
        },
        'AUTH_PARAMS': {
            'access_type': 'online',
        }
    }
}

# Google OAuth redirect URLs
GOOGLE_OAUTH_SUCCESS_REDIRECT_URL = 'http://localhost:3000/auth/callback'
GOOGLE_OAUTH_ERROR_REDIRECT_URL = 'http://localhost:3000/auth/error'


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
TWOFACTOR_ENFORCE_FOR_ALL_USERS = False
TWOFACTOR_DEFAULT_METHOD = 'EMAIL'  # 'EMAIL' or 'PHONE'
TWOFACTOR_CODE_EXPIRATION_SECONDS = 600  # 10 minutes
TWOFACTOR_MAX_FAILED_ATTEMPTS = 5
TWOFACTOR_TEMPORARY_TOKEN_LIFETIME_MINUTES = 10
