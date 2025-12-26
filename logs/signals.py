from decimal import Decimal
from django.db.models.signals import post_save, pre_save, pre_delete
from django.dispatch import receiver
from .models import ActionLog
from .middleware import get_current_user  # Import the helper function

MONITORED_MODELS = {
    "User",
    "Clinic",
    "ClinicUserPermission",
    "CertificateApplication",
    "Doctor",
    "Announcement",
}


# Signal handler to store old values before saving the instance
@receiver(pre_save)
def capture_old_values(sender, instance, **kwargs):
    if instance.pk:  # Only for existing objects (updates)
        try:
            instance._old_instance = sender.objects.get(pk=instance.pk)
        except sender.DoesNotExist:
            instance._old_instance = None


# Signal handler for model creation and updates
@receiver(post_save)
def log_create_update(sender, instance, created, **kwargs):
    if sender == ActionLog:
        return

    action = "CREATE" if created else "UPDATE"

    if sender.__name__ in MONITORED_MODELS:
        changes = get_model_changes(instance, created)
        # 對於 CREATE 操作，即使 changes 為空也應該記錄
        if changes != "" or created:
            ActionLog.objects.create(
                user=get_current_user(),
                model_name=sender.__name__,
                action=action,
                object_id=instance.pk,
                changes=changes if changes else str(instance),
            )


# Signal handler for model deletion
@receiver(pre_delete)
def log_delete(sender, instance, **kwargs):
    # Avoid logging actions for the ActionLog model itself
    if sender == ActionLog:
        return

    ActionLog.objects.create(
        user=get_current_user(),  # Now we get the current request user
        model_name=sender.__name__,
        action="DELETE",
        object_id=instance.pk,
        changes=str(instance),
    )


# Helper functions
def get_model_changes(instance, created=False):
    changes = []

    if hasattr(instance, "_old_instance") and instance._old_instance is not None:
        # UPDATE operation: compare old and new values
        old_instance = instance._old_instance  # The old state of the model

        for field in instance._meta.fields:
            field_name = field.name
            if (
                field_name != "image"
                and field_name != "last_login"
                and field_name != "password"
                and field_name != "last_login"
                and field_name != "update_time"
            ):
                new_value = getattr(instance, field_name)
                old_value = getattr(old_instance, field_name)

                if type(new_value) is str and type(old_value) is Decimal:
                    new_value = str(new_value)
                    old_value = str(old_value)

                if (new_value != old_value) and not (
                    old_value is None and new_value is None
                ):
                    changes.append(f"{field_name}: {old_value} -> {new_value}\n")

        # Return all changes as a single string
        return "".join(changes) if changes else ""

    # For CREATE operations, return a string representation of the instance
    if created:
        # 對於 CREATE 操作，返回實例的關鍵信息
        if hasattr(instance, "__str__"):
            return str(instance)
        else:
            # 如果沒有 __str__ 方法，返回模型名稱和主鍵
            return f"{instance.__class__.__name__} #{instance.pk}"

    # For UPDATE operations without old_instance, return empty string
    return ""
