"""
Testing settings for Django boilerplate.

Inherits from base.py and adds testing-specific configurations.
"""

from .base import *

# Debug mode
DEBUG = False

# Email backend for testing (memory)
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

# Use faster password hasher for tests
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

# In-memory SQLite database for faster tests
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

# Disable activation emails for testing to allow immediate login
DJOSER['SEND_ACTIVATION_EMAIL'] = False
