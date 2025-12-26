"""
Enum definitions for user-related choices.
"""

from django.db import models
from django.utils.translation import gettext_lazy as _


class UserRole(models.TextChoices):
    """
    User role choices for permission management.
    """

    SUPER_ADMIN = "SUPER_ADMIN", _("系統超級管理員")
    ADMIN = "ADMIN", _("系統管理員")
    CLINIC_ADMIN = "CLINIC_ADMIN", _("診所管理員")
    CLINIC_STAFF = "CLINIC_STAFF", _("診所員工")
    CLIENT = "CLIENT", _("客戶")


class OccupationCategory:
    """
    職業類別枚舉
    """

    # 根據實際需求添加職業類別選項
    DOCTOR = "doctor"
    NURSE = "nurse"
    CONSULTANT = "consultant"
    ADMINISTRATOR = "administrator"
    OTHER = "other"

    CHOICES = [
        (DOCTOR, _("醫師")),
        (NURSE, _("護理師")),
        (CONSULTANT, _("諮詢師")),
        (ADMINISTRATOR, _("行政人員")),
        (OTHER, _("其他")),
    ]


class InformationSource:
    """
    資訊來源枚舉（怎麼知道LBV認證活動資訊）
    """

    FRIENDS_FAMILY = "friends_family"
    SOCIAL_MEDIA = "social_media"
    INTERNET_SEARCH = "internet_search"
    OTHER = "other"

    CHOICES = [
        (FRIENDS_FAMILY, _("親友推薦")),
        (SOCIAL_MEDIA, _("社群媒體")),
        (INTERNET_SEARCH, _("網路搜尋")),
        (OTHER, _("其他")),
    ]
