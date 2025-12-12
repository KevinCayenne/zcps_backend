from django.contrib import admin
from .models import ActionLog


class ActionLogAdmin(admin.ModelAdmin):
    list_display = ("user", "model_name", "action", "timestamp", "object_id")
    list_filter = ("action", "model_name", "timestamp")
    search_fields = ("model_name", "object_id", "changes")
    readonly_fields = ("timestamp",)
    date_hierarchy = "timestamp"


admin.site.register(ActionLog, ActionLogAdmin)
