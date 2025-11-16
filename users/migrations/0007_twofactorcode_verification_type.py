# Generated migration for TwoFactorCode verification_type field

from django.db import migrations, models


def set_existing_codes_to_twofactor(apps, schema_editor):
    """Set all existing codes to TWO_FACTOR verification type."""
    TwoFactorCode = apps.get_model('users', 'TwoFactorCode')
    TwoFactorCode.objects.all().update(verification_type='TWO_FACTOR')


def reverse_set_existing_codes(apps, schema_editor):
    """No-op on rollback."""
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0006_user_2fa_method_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='twofactorcode',
            name='verification_type',
            field=models.CharField(choices=[('TWO_FACTOR', 'Two-Factor Authentication')], default='TWO_FACTOR', help_text='Type of verification this code is used for', max_length=20),
        ),
        migrations.RunPython(set_existing_codes_to_twofactor, reverse_set_existing_codes),
    ]
