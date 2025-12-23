from django.apps import AppConfig


class ClinicConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "clinic"

    def ready(self):
        """
        當應用程序準備就緒時，導入 signals
        """
        import clinic.signals  # noqa
