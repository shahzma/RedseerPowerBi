# Generated by Django 4.0.5 on 2023-03-09 07:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('LoginAPI', '0036_companydomainmodel_otp_access'),
    ]

    operations = [
        migrations.AlterField(
            model_name='companydomainmodel',
            name='otp_access',
            field=models.BooleanField(default=True),
        ),
    ]
