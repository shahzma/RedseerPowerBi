# Generated by Django 4.0.5 on 2023-03-02 10:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('LoginAPI', '0033_alter_newreportaccessmodel_players_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='newreportmodel',
            name='filter',
            field=models.CharField(blank=True, default=None, max_length=200, null=True),
        ),
    ]
