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

    # 職業類別選項
    ADMIN_OFFICE = "admin_office"
    EDUCATION = "education"
    MEDICAL = "medical"
    FINANCE = "finance"
    LEGAL = "legal"
    TECH = "tech"
    MARKETING = "marketing"
    SALES = "sales"
    SERVICE = "service"
    DESIGN = "design"
    MANUFACTURING = "manufacturing"
    AGRICULTURE = "agriculture"
    TRANSPORT = "transport"
    SELF_EMPLOYED = "self_employed"
    HOMEMAKER = "homemaker"
    STUDENT = "student"
    RETIRED = "retired"
    CUSTOM = "custom"  # 自定義選項，允許用戶填寫
    OTHER = "other"

    CHOICES = [
        (ADMIN_OFFICE, _("行政／白領辦公")),
        (EDUCATION, _("教育／學術／培訓")),
        (MEDICAL, _("醫療／護理／醫技")),
        (FINANCE, _("金融／會計／稅務")),
        (LEGAL, _("法律／專業顧問")),
        (TECH, _("科技／工程／資訊")),
        (MARKETING, _("行銷／廣告／媒體")),
        (SALES, _("業務／銷售")),
        (SERVICE, _("服務業／餐飲／零售")),
        (DESIGN, _("設計／藝術／創意產業")),
        (MANUFACTURING, _("製造業／工業技術／工廠")),
        (AGRICULTURE, _("農林漁牧／戶外工作")),
        (TRANSPORT, _("交通運輸／物流")),
        (SELF_EMPLOYED, _("自營商／自由工作者")),
        (HOMEMAKER, _("家庭主婦／全職家長")),
        (STUDENT, _("學生")),
        (RETIRED, _("退休")),
        (CUSTOM, _("其他（請填寫）")),
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


class Gender:
    """
    性別枚舉
    """

    MALE = "male"
    FEMALE = "female"
    OTHER = "other"

    CHOICES = [
        (MALE, _("男性")),
        (FEMALE, _("女性")),
        (OTHER, _("其他")),
    ]
