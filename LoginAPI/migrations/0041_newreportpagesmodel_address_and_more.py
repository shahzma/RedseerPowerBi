# Generated by Django 4.0.5 on 2023-03-29 08:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('LoginAPI', '0040_alter_newreportmodel_filter'),
    ]

    operations = [
        migrations.AddField(
            model_name='newreportpagesmodel',
            name='address',
            field=models.TextField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='newreportpagesmodel',
            name='has_address',
            field=models.BooleanField(default=False),
        ),
    ]
