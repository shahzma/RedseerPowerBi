# Generated by Django 4.0.5 on 2023-02-20 05:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('LoginAPI', '0022_newreportpagesmodel_info'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='newreportpagesmodel',
            name='info',
        ),
        migrations.AddField(
            model_name='newreportmodel',
            name='info',
            field=models.TextField(blank=True, default=None, null=True),
        ),
    ]
