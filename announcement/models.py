from django.db import models
from config.abstract import BaseModel
from django.utils.translation import gettext_lazy as _

class Announcement(BaseModel):
    title = models.CharField(max_length=255, verbose_name=_('標題'))
    content = models.JSONField(default=dict, verbose_name=_('內容'))
    is_active = models.BooleanField(default=True, verbose_name=_('是否生效'))