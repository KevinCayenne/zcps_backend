"""
Development settings for Django boilerplate.

Inherits from base.py and adds development-specific configurations.
"""

from .base import *
from decouple import config

# Debug mode
DEBUG = True

# Email backend for development
# Can be configured via .env to use either console (default) or SMTP
EMAIL_BACKEND = config('EMAIL_BACKEND', default='django.core.mail.backends.console.EmailBackend')
EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')

# Allow all hosts in development
ALLOWED_HOSTS = ['*']

# CORS settings for development
CORS_ALLOW_ALL_ORIGINS = True  # Allow all origins in development
CORS_ALLOW_CREDENTIALS = True  # Allow cookies to be sent with cross-origin requests
