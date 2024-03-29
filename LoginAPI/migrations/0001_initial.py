# Generated by Django 4.0.5 on 2022-07-27 10:27

import LoginAPI.models
import datetime
import django.contrib.auth.models
import django.contrib.auth.validators
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='ClientModel',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('company_email', models.EmailField(max_length=100)),
                ('login_mode', models.BooleanField(default=False)),
            ],
            options={
                'db_table': 'ClientModel',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='ReportModel',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('report_name', models.CharField(max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('username', models.CharField(error_messages={'unique': 'A user with that username already exists.'}, help_text='Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.', max_length=150, unique=True, validators=[django.contrib.auth.validators.UnicodeUsernameValidator()], verbose_name='username')),
                ('first_name', models.CharField(blank=True, max_length=150, verbose_name='first name')),
                ('last_name', models.CharField(blank=True, max_length=150, verbose_name='last name')),
                ('email', models.EmailField(blank=True, max_length=254, verbose_name='email address')),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this user should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('phone', models.CharField(blank=True, max_length=255, null=True)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'verbose_name': 'user',
                'verbose_name_plural': 'users',
                'abstract': False,
            },
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.CreateModel(
            name='ReportAccessModel',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('email', models.EmailField(max_length=100)),
                ('start_date', models.DateField(default=datetime.date.today)),
                ('end_date', models.DateField(default=LoginAPI.models.get_deadline)),
                ('client_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='LoginAPI.clientmodel')),
                ('report_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='LoginAPI.reportmodel')),
            ],
            options={
                'db_table': 'ReportAccessModel',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='CompanyDomainModel',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('domain_name', models.CharField(max_length=100)),
                ('client_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='LoginAPI.clientmodel')),
            ],
            options={
                'db_table': 'CompanyDomainModel',
                'managed': True,
            },
        ),
    ]
