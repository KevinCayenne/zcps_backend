"""
Production settings for Django boilerplate.

Inherits from base.py and adds production-specific configurations.
"""

import os
import dj_database_url
from .base import *

# Debug mode
DEBUG = False

# Email backend for production (SMTP)
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = os.environ.get('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.environ.get('EMAIL_PORT', 587))
EMAIL_USE_TLS = os.environ.get('EMAIL_USE_TLS', 'True').lower() == 'true'
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', '')

# Security settings
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True

# Allowed hosts should be configured via environment variable in production
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')

if not DATABASE_URL:
    raise ValueError(
        "DATABASE_URL environment variable is required in production. "
        "Add it to your .env file: DATABASE_URL=postgres://user:pass@host:5432/dbname"
    )

DATABASES['default'] = dj_database_url.config(
    default=DATABASE_URL,
    engine='django.db.backends.postgresql',
    conn_max_age=600
)
