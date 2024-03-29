# Generated by Django 4.0.5 on 2023-02-28 08:56

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('LoginAPI', '0028_usercurrencymodel_year'),
    ]

    operations = [
        migrations.CreateModel(
            name='NewReportAccessModel',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('client_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='LoginAPI.clientmodel')),
                ('report_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='LoginAPI.newreportmodel')),
            ],
            options={
                'db_table': 'NewReportAccessModel',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='NewReportPageAccessModel',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('page_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='LoginAPI.newreportpagesmodel')),
                ('report_access_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='LoginAPI.newreportaccessmodel')),
            ],
            options={
                'db_table': 'NewReportPageAccessModel',
                'managed': True,
            },
        ),
    ]
