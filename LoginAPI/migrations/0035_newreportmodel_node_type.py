# Generated by Django 4.0.5 on 2023-03-06 06:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('LoginAPI', '0034_newreportmodel_filter'),
    ]

    operations = [
        migrations.AddField(
            model_name='newreportmodel',
            name='node_type',
            field=models.CharField(blank=True, default=None, max_length=200, null=True),
        ),
    ]