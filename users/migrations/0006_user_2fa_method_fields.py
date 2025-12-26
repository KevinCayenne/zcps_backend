# Generated migration for User model 2FA method fields

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0005_create_twofactorsettings"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="email_verified",
            field=models.BooleanField(
                default=False, help_text="Whether user email has been verified"
            ),
        ),
        migrations.AddField(
            model_name="user",
            name="preferred_2fa_method",
            field=models.CharField(
                blank=True,
                choices=[("EMAIL", "Email"), ("PHONE", "Phone")],
                help_text="User preferred 2FA method (null uses system default)",
                max_length=20,
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="user",
            name="phone_number_verified",
            field=models.BooleanField(
                default=False,
                help_text="Whether user phone number has been verified for 2FA",
            ),
        ),
    ]
