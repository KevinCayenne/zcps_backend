"""
Custom User model for Django boilerplate.

Extends Django's AbstractUser to add custom fields and functionality.
"""

from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """
    Custom User model extending AbstractUser.

    Adds phone_number field and makes email required and unique.
    Includes created_at and updated_at timestamps for auditing.
    """

    # Override email to make it required and unique
    email = models.EmailField(
        'email address',
        unique=True,
        blank=False,
        error_messages={
            'unique': 'A user with this email already exists.',
        }
    )

    # Add phone_number field supporting international format
    phone_number = models.CharField(
        max_length=17,
        blank=True,
        null=True,
        help_text='Phone number in international format (e.g., +1 234 5678901)'
    )

    # Add timestamp fields for auditing
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'user'
        verbose_name_plural = 'users'
        ordering = ['-created_at']

    def __str__(self):
        """Return string representation of user."""
        return self.email if self.email else self.username
