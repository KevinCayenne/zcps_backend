from django.db import models
from config.abstract import BaseModel
from django.utils.translation import gettext_lazy as _
from users.models import User

class Announcement(BaseModel):
    title = models.CharField(max_length=255, verbose_name=_('標題'))
    content = models.JSONField(default=dict, verbose_name=_('內容'))
    is_active = models.BooleanField(default=True, verbose_name=_('是否發布'))
    active_start_time = models.DateTimeField(blank=True, null=True, verbose_name=_('生效時間'))
    active_end_time = models.DateTimeField(blank=True, null=True, verbose_name=_('失效時間'))
    active_member = models.ManyToManyField(User, blank=True, verbose_name=_('發布人'))
    is_send_email = models.BooleanField(default=False, verbose_name=_('是否發送電子郵件通知'))
    email_sent_at = models.DateTimeField(blank=True, null=True, verbose_name=_('Email 發送時間'), help_text=_('記錄 email 發送的時間，用於確保同一公告僅發送一次'))
    html_cache = models.TextField(blank=True, verbose_name=_('HTML 快取'))

    class Meta:
        verbose_name = _('公告')
        verbose_name_plural = _('公告')

    def __str__(self):
        return self.title

