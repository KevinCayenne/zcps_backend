"""
Development settings for Django boilerplate.

Inherits from base.py and adds development-specific configurations.
"""

from .base import *

# Debug mode
DEBUG = True

# Email backend for development (console output)
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Allow all hosts in development
ALLOWED_HOSTS = ['*']
