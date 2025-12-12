from django.db import models
from django.conf import settings
from datetime import datetime
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import Group


class BaseModel(models.Model):
    """
    Abstract Model，包含建立者（creator，可為空值）、建立時間（create_time）和更新時間（update_time）。
    """

    create_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        verbose_name="建立者",
        related_name="%(app_label)s_%(class)s_ownership",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    create_time = models.DateTimeField(
        verbose_name="建立時間", auto_now_add=True, null=True
    )
    update_time = models.DateTimeField(
        verbose_name="更新時間", auto_now=True, null=True
    )

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        self.update_time = datetime.now()
        super().save(*args, **kwargs)


class BaseGroupModel(BaseModel):
    """
    群組
    """

    groups = models.ManyToManyField(
        Group,
        blank=True,
        related_name="%(class)s_set",
    )

    class Meta:
        abstract = True