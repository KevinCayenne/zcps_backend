# Generated migration for TwoFactorSettings singleton model

from django.conf import settings
from django.db import migrations, models


def create_initial_settings(apps, schema_editor):
    """Create initial TwoFactorSettings record with values from Django settings."""
    TwoFactorSettings = apps.get_model("users", "TwoFactorSettings")

    # Create singleton record with settings from Django config
    TwoFactorSettings.objects.create(
        enforce_2fa_for_all_users=getattr(settings, "REQUIRE_2FA_FOR_ALL_USERS", False),
        default_2fa_method="EMAIL",
        code_expiration_seconds=getattr(settings, "TWOFACTOR_CODE_EXPIRATION", 600),
        max_failed_attempts=getattr(settings, "TWOFACTOR_MAX_FAILED_ATTEMPTS", 5),
        temporary_token_lifetime_minutes=getattr(
            settings, "TWOFACTOR_TEMPORARY_TOKEN_LIFETIME", 10
        ),
    )


def reverse_create_initial_settings(apps, schema_editor):
    """Remove TwoFactorSettings record on migration rollback."""
    TwoFactorSettings = apps.get_model("users", "TwoFactorSettings")
    TwoFactorSettings.objects.all().delete()


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0004_twofactorcode"),
    ]

    operations = [
        migrations.CreateModel(
            name="TwoFactorSettings",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "enforce_2fa_for_all_users",
                    models.BooleanField(
                        default=False,
                        help_text="When enabled, all users must enable 2FA to access the system",
                    ),
                ),
                (
                    "default_2fa_method",
                    models.CharField(
                        choices=[("EMAIL", "Email"), ("PHONE", "Phone (coming soon)")],
                        default="EMAIL",
                        help_text="Default 2FA method for users who have not set a preference",
                        max_length=20,
                    ),
                ),
                (
                    "code_expiration_seconds",
                    models.PositiveIntegerField(
                        default=600,
                        help_text="Number of seconds before a 2FA code expires (default: 600 = 10 minutes)",
                    ),
                ),
                (
                    "max_failed_attempts",
                    models.PositiveIntegerField(
                        default=5,
                        help_text="Maximum number of failed verification attempts before code is locked",
                    ),
                ),
                (
                    "temporary_token_lifetime_minutes",
                    models.PositiveIntegerField(
                        default=10,
                        help_text="Lifetime of temporary 2FA tokens in minutes (used during login flow)",
                    ),
                ),
            ],
            options={
                "verbose_name": "Two-Factor Authentication Settings",
                "verbose_name_plural": "Two-Factor Authentication Settings",
                "abstract": False,
            },
        ),
        migrations.RunPython(create_initial_settings, reverse_create_initial_settings),
    ]
