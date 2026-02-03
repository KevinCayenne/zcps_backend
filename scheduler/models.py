from croniter import croniter
from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from config.abstract import BaseModel


class NotificationTask(BaseModel):
    name = models.CharField(_("Task Name"), max_length=255)
    enable = models.BooleanField(_("Enable"), default=True)
    period = models.CharField(
        _("Cron Period"), max_length=100, help_text=_("Cron expression")
    )
    start_time = models.DateTimeField(_("Start Time"))
    end_time = models.DateTimeField(_("End Time"), null=True, blank=True)
    contents = models.JSONField(
        _("Contents"), default=list
    )  # [{"channel": "sms", "body": "...", "title": "..."}]
    roles = models.JSONField(_("Roles"), default=list, blank=True)
    targets = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        verbose_name=_("Targets"),
        related_name="notification_tasks_targets",
        blank=True,
    )

    class Meta:
        verbose_name = _("Notification Task")
        verbose_name_plural = _("Notification Tasks")

    def __str__(self):
        return self.name

    def clean(self):
        super().clean()
        if self.period and not croniter.is_valid(self.period):
            raise ValidationError({"period": _("Invalid cron expression")})

        if self.start_time and self.end_time and self.start_time > self.end_time:
            raise ValidationError({"end_time": _("End time must be after start time")})
