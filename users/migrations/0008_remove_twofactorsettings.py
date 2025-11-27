# Generated migration for removing TwoFactorSettings model

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0007_twofactorcode_verification_type'),
    ]

    operations = [
        migrations.DeleteModel(
            name='TwoFactorSettings',
        ),
    ]
