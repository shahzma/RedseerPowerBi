# Generated by Django 4.0.5 on 2023-02-09 14:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('LoginAPI', '0019_newreportmodel_newreportpagesmodel'),
    ]

    operations = [
        migrations.AddField(
            model_name='reportpagesmodel',
            name='embed',
            field=models.TextField(blank=True, default=None, null=True),
        ),
    ]
