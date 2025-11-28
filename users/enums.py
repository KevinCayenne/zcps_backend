"""
Enum definitions for user-related choices.
"""

from django.db import models
from django.utils.translation import gettext_lazy as _


class UserRole(models.TextChoices):
    """
    User role choices for permission management.
    """
    SUPER_ADMIN = 'SUPER_ADMIN', _('系統超級管理員')
    ADMIN = 'ADMIN', _('系統管理員')
    CLINIC_ADMIN = 'CLINIC_ADMIN', _('診所管理員')
    CLINIC_STAFF = 'CLINIC_STAFF', _('診所員工')
    CLIENT = 'CLIENT', _('客戶')

