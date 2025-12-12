from django.db import models
from django.conf import settings


class ActionLog(models.Model):
    ACTION_CHOICES = [
        ("CREATE", "Create"),
        ("UPDATE", "Update"),
        ("DELETE", "Delete"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name='使用者'
    )
    model_name = models.CharField(max_length=100)
    action = models.CharField(max_length=6, choices=ACTION_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    object_id = models.CharField(max_length=255)  # Store the primary key of the object
    changes = models.TextField(
        blank=True, null=True
    )  # Optional: Store details of the change

    def __str__(self):
        return f"{self.model_name} {self.action} by {self.user or 'Anonymous'} on {self.timestamp}"
