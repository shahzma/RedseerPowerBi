# Generated by Django 4.0.5 on 2022-11-14 06:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('LoginAPI', '0009_alter_reportaccessmodel_end_date_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='reportaccessmodel',
            name='players',
            field=models.ManyToManyField(to='LoginAPI.player'),
        ),
    ]
