from django.db import models
from django.utils.translation import gettext_lazy as _
from config.abstract import BaseModel
from users.models import User

class Clinic(BaseModel):
    """
    Clinic model.
    """
    name = models.CharField(max_length=255, verbose_name=_('診所名稱'))
    address = models.CharField(max_length=255, verbose_name=_('地址'), blank=True, null=True)
    phone = models.CharField(max_length=255, verbose_name=_('電話'), blank=True, null=True)
    email = models.EmailField(max_length=255, verbose_name=_('電子郵件'), blank=True, null=True)
    website = models.URLField(max_length=255, verbose_name=_('網站'), blank=True, null=True)

    class Meta:
        verbose_name = _('診所')
        verbose_name_plural = _('診所')
        ordering = ['-name']


class ClinicUserPermission(BaseModel):
    """
    Clinic user permission model.
    """
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        verbose_name=_('用戶'), 
        related_name='clinic_user_permissions'
    )
    clinic = models.ForeignKey(
        Clinic, 
        on_delete=models.CASCADE, 
        verbose_name=_('診所'), 
        related_name='clinic_user_permissions'
    )
    class Meta:
        verbose_name = _('診所用戶權限')
        verbose_name_plural = _('診所用戶權限')
