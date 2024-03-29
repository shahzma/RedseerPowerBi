# Generated by Django 4.0.5 on 2022-07-28 10:43

from django.db import migrations, models
import django.db.models.deletion
import mptt.fields


class Migration(migrations.Migration):

    dependencies = [
        ('LoginAPI', '0003_iconmodel'),
    ]

    operations = [
        migrations.CreateModel(
            name='ReportPagesModel',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('page_name', models.CharField(max_length=45)),
                ('link', models.CharField(max_length=45)),
                ('order', models.IntegerField(blank=True, default=1, null=True)),
                ('lft', models.PositiveIntegerField(editable=False)),
                ('rght', models.PositiveIntegerField(editable=False)),
                ('tree_id', models.PositiveIntegerField(db_index=True, editable=False)),
                ('level', models.PositiveIntegerField(editable=False)),
                ('icon', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='LoginAPI.iconmodel')),
                ('parent', mptt.fields.TreeForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='children', to='LoginAPI.reportpagesmodel')),
                ('report', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='LoginAPI.reportmodel')),
            ],
            options={
                'db_table': 'report_pages_model',
                'managed': True,
            },
        ),
    ]
