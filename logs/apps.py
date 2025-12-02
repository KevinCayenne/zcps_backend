from django.apps import AppConfig


class LogsConfig(AppConfig):
    name = "logs"

    def ready(self):
        import logs.signals  # noqa: F401 - Importing signals to register them
