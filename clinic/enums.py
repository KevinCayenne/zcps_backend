"""
Enums for Clinic app.
"""

from django.utils.translation import gettext_lazy as _


class CertificateApplicationStatus:
    """
    證書申請狀態枚舉
    """
    PENDING = 'pending'
    VERIFIED = 'verified'
    ISSUED = 'issued'
    EXPIRED = 'expired'
    CANCELLED = 'cancelled'
    
    CHOICES = [
        (PENDING, _('待驗證')),
        (VERIFIED, _('已驗證')),
        (ISSUED, _('已發證')),
        (EXPIRED, _('已過期')),
        (CANCELLED, _('已取消')),
    ]
