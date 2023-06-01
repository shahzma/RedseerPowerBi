# Generated by Django 4.0.5 on 2023-05-31 12:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('LoginAPI', '0050_newreportpagesmodel_excel_access'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='newreportpagesmodel',
            name='excel_access',
        ),
        migrations.AddField(
            model_name='newreportaccessmodel',
            name='excel_access',
            field=models.BooleanField(default=False),
        ),
    ]
