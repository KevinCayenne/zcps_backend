"""
Development settings for Django boilerplate.

Inherits from base.py and adds development-specific configurations.
"""

import dj_database_url
from .base import DATABASES, DATABASE_URL, os

# Debug mode
DEBUG = True

# Email backend for development
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = os.environ.get("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", 587))
EMAIL_USE_TLS = os.environ.get("EMAIL_USE_TLS", "True").lower() == "true"
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD", "")

# Allow all hosts in development
ALLOWED_HOSTS = ["*"]

# CORS settings for development
CORS_ALLOW_ALL_ORIGINS = True  # Allow all origins in development
CORS_ALLOW_CREDENTIALS = True  # Allow cookies to be sent with cross-origin requests

if not DATABASE_URL:
    raise ValueError(
        "DATABASE_URL environment variable is required. "
        "Add it to your .env file: DATABASE_URL=postgres://user:pass@localhost:5432/dbname"
    )

DATABASES["default"] = dj_database_url.config(
    default=DATABASE_URL, engine="django.db.backends.postgresql"
)

print("DATABASES: ", DATABASES)
