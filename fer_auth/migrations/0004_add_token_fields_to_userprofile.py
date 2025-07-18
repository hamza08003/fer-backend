# Generated by Django 5.2.4 on 2025-07-08 17:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fer_auth', '0003_remove_userprofile_created_at_and_updated_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='email_token_created_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='email_token_expires_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='email_verification_token',
            field=models.UUIDField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='password_reset_token',
            field=models.UUIDField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='password_token_created_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='password_token_expires_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='password_token_used',
            field=models.BooleanField(default=False),
        ),
    ]
